/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"
#include "sr_dumper.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_locker));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_locker));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_locker));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_locker));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_locker));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_locker));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%d\t",entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */


void *sr_rip_timeout(void *sr_ptr) {
    printf("send_rip_timeout() called \n");
    struct sr_instance *sr = sr_ptr;
    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_locker));
        /* Lab5: Fill your code here */

        /* struct sr_rt* rt_walker = 0;
        if(sr->routing_table == 0)
        {
            printf(" *warning* Routing table empty \n");
            pthread_mutex_unlock(&(sr->rt_locker));
            return 
        } */
        
        struct sr_rt* rt_walker = sr->routing_table;
        while(rt_walker){
            if (rt_walker->metric < INFINITY) {
                time_t now;
                time(&now);
                if (difftime(now, rt_walker->updated_time) > 20) {
                    rt_walker->metric = INFINITY;
                    /* printf("Timeout: "); */
                    sr_print_routing_entry(rt_walker);
                }
            }
            rt_walker = rt_walker->next;
        }

        /* check status of router's own interfaces */
        struct sr_if* interface = sr->if_list;
        while (interface) {
            uint32_t status = sr_obtain_interface_status(sr, interface->name);
            printf("Interface status %s: %d \n", interface->name, status);
            if (status == 0) {
                printf("(Timeout) Interface %s is down \n", interface->name);
                /*
                struct in_addr dest_addr;
                dest_addr.s_addr = (interface->ip & interface->mask);
                */
                struct sr_rt* rt_walker = 0;
                rt_walker = sr->routing_table;
                while(rt_walker){
                  /* rt_walker->dest.s_addr == dest_addr.s_addr */
                  if (strcmp(interface->name, rt_walker->interface) == 0) {
                      rt_walker->metric = INFINITY;
                      /* printf("Timeout: "); */
                      sr_print_routing_entry(rt_walker);
                  }
                  rt_walker = rt_walker->next;
                }
            } else {
                printf("(Timeout) Interface %s is up \n", interface->name);
                int found = 0;
                struct sr_rt* rt_walker = 0;
                rt_walker = sr->routing_table;
                while(rt_walker){
                  if ((rt_walker->dest.s_addr & rt_walker->mask.s_addr) == (interface->ip & interface->mask) && rt_walker->mask.s_addr == interface->mask) {
                    printf("timeout update time\n");
                    rt_walker->updated_time = time(NULL);
                    rt_walker->metric = 0;
                    rt_walker->gw.s_addr = 0;
                    strcpy(rt_walker->interface, interface->name);
                    found = 1;
                  }
                  rt_walker = rt_walker->next;
                }
                if (found == 0) {
                  struct in_addr dest_addr;
                  dest_addr.s_addr = interface->ip;
                  struct in_addr gw_addr;
                  gw_addr.s_addr = 0x0;
                  struct in_addr mask_addr;
                  mask_addr.s_addr = interface->mask;
                  sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, 0, interface->name);
                }
                /* check if routing table contains this interface */
                
            }
            interface = interface->next;
        }

        /* call send_rip_response */
        send_rip_response(sr);
        
        pthread_mutex_unlock(&(sr->rt_locker));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr){
  printf("send_rip_request() called \n");
  pthread_mutex_lock(&(sr->rt_locker));
  /* Lab5: Fill your code here */
  /* build rip request packet */
  uint8_t *packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_rip_pkt_t *rip_hdr = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) );
  struct sr_if *interface = sr->if_list;

  unsigned char broadcast[ETHER_ADDR_LEN];
  uint32_t broadcast_ip = 0xffffffff;
  int i;
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
      broadcast[i] = 0xff;
  }

  /* build ethernet header */
  memcpy(eth_hdr->ether_dhost, broadcast, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);

  /* build ip header */
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
  ip_hdr->ip_src = interface->ip;
  ip_hdr->ip_dst = htonl(broadcast_ip);
  ip_hdr->ip_id = htons(0);
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_udp;
  printf("IP protocol (rip request): %d \n", ip_hdr->ip_p);
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum((uint8_t *) ip_hdr, sizeof(sr_ip_hdr_t));

  /* build udp header */
  udp_hdr->port_src = htons(520);
  udp_hdr->port_dst = htons(520);
  udp_hdr->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
  udp_hdr->udp_sum = 0;
  /* TODO: check if size is correct */
  udp_hdr->udp_sum = cksum((uint8_t *) udp_hdr, sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));

  /* build rip header */
  /* TODO: check if values are correct */
  rip_hdr->command = 1;
  rip_hdr->version = 2;
  rip_hdr->unused = 0;
  /*
  for(i=0; i<MAX_NUM_ENTRIES; i++) {
    rip_hdr->entries[i].afi = htons(0);
    rip_hdr->entries[i].tag = htons(0);
    rip_hdr->entries[i].address = htons(0);
    rip_hdr->entries[i].mask = htons(0);
    rip_hdr->entries[i].next_hop = htons(0);
    rip_hdr->entries[i].metric = INFINITY;
  } */

  rip_hdr->entries[0].afi = htons(0);
  rip_hdr->entries[0].tag = htons(0);
  rip_hdr->entries[0].address = 0;
  rip_hdr->entries[0].mask = 0;
  rip_hdr->entries[0].next_hop = 0;
  rip_hdr->entries[0].metric = htonl(INFINITY);

  /* send rip packet to all interfaces */
  while (interface) {
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    ip_hdr->ip_src = interface->ip;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((uint8_t *) ip_hdr, sizeof(sr_ip_hdr_t));
    /* TODO: check if should recalculate udp checksum */
    /*
    udp_hdr->udp_sum = 0;
    udp_hdr->udp_sum = cksum((uint8_t *)udp_hdr, sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
    */

    int err = sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t), interface->name);
    if (err) {
      fprintf(stderr, "Error sending packet: %d\n", err);
    }
    interface = interface->next;
  }
  pthread_mutex_unlock(&(sr->rt_locker));
}

void send_rip_response(struct sr_instance *sr){
    printf("send_rip_response() called \n");
    pthread_mutex_lock(&(sr->rt_locker));

        
    unsigned char broadcast[ETHER_ADDR_LEN];
    uint32_t broadcast_ip = 0xffffffff;
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        broadcast[i] = 0xff;
    }
    /* Lab5: Fill your code here */
    /* build rip response packet */
    struct sr_if *interface = sr->if_list;
    while (interface) {
      uint8_t *packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      sr_rip_pkt_t *rip_hdr = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));

      /* build ethernet header */
      memcpy(eth_hdr->ether_dhost, broadcast, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
      eth_hdr->ether_type = htons(ethertype_ip);

      /* build ip header */
      ip_hdr->ip_v = 4;
      ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
      ip_hdr->ip_tos = 0;
      ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
      ip_hdr->ip_src = interface->ip;
      ip_hdr->ip_dst = htonl(broadcast_ip);
      ip_hdr->ip_id = htons(0);
      ip_hdr->ip_off = htons(IP_DF);
      ip_hdr->ip_ttl = 64;
      ip_hdr->ip_p = ip_protocol_udp;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum((uint8_t *)ip_hdr, sizeof(sr_ip_hdr_t));

        /* build udp header */
      udp_hdr->port_src = htons(520);
      udp_hdr->port_dst = htons(520);
      udp_hdr->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
      udp_hdr->udp_sum = 0;
      udp_hdr->udp_sum = cksum((uint8_t *)udp_hdr, sizeof(sr_udp_hdr_t));

      /* build rip header with split horizon*/
      /* TODO: work out split horizon */
      rip_hdr->command = 2;
      rip_hdr->version = 2;
      rip_hdr->unused = 0;

      struct sr_rt *rt = sr->routing_table;
      sr_print_routing_table(sr);
      int i =0;
      while (rt) {
          rip_hdr->entries[i].afi = htons(2);
          rip_hdr->entries[i].tag = htons(0);
          rip_hdr->entries[i].address = rt->dest.s_addr;
          rip_hdr->entries[i].mask = rt->mask.s_addr;
          rip_hdr->entries[i].next_hop = rt->gw.s_addr;

          if((interface->ip & rt->mask.s_addr) == (rt->gw.s_addr & rt->mask.s_addr)){
            printf("reverse poisoning split horizon. Set metric to infinity.\n");
            rip_hdr->entries[i].metric = htonl(INFINITY);
          }
          else{
            rip_hdr->entries[i].metric = htonl(rt->metric);
          }
          i++;
        rt = rt->next;
      }
      int err = sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t), interface->name);
      if (err) {
        fprintf(stderr, "Error sending packet: %d\n", err);
      } else {
        printf("Sent!\n");
      }
      free(packet);
      interface = interface->next;
    }

    pthread_mutex_unlock(&(sr->rt_locker));
}

void update_route_table(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
    pthread_mutex_lock(&(sr->rt_locker));
    printf("update_route_table() called\n");
    /* Lab5: Fill your code here */
    sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    int isUpdated = 0;
    
    int i = 0;
    for(i = 0; i < MAX_NUM_ENTRIES; i++){
      struct sr_rt *entry = NULL;
      struct entry *rp_entry = &(rip_hdr->entries[i]);
      if(rp_entry->address == 0){
        continue;
      }
      uint32_t metric_new = ntohl(rp_entry->metric) + 1;
      if(metric_new >= INFINITY){
        continue;
      }
      for(entry = sr->routing_table; entry!=NULL; entry = entry->next){
        if((rp_entry->address & rp_entry->mask) == (entry->dest.s_addr & entry->mask.s_addr) ){
          printf("Found entry in routing table\n");
            if (entry->gw.s_addr == ip_hdr->ip_src || metric_new < entry->metric){
              printf("Packet is from same router as entry or metric is less than current metric; update entry\n");
              if (metric_new != entry->metric || ip_hdr->ip_src != entry->gw.s_addr || strcmp(entry->interface, interface) !=0) {
                printf("No changes\n");
                isUpdated = 1;
              }
              entry->dest.s_addr = rp_entry->address;
              entry->metric = metric_new;
              entry->gw.s_addr = ip_hdr->ip_src;
              entry->mask.s_addr = rp_entry->mask;
              memcpy(entry->interface, interface, sr_IFACE_NAMELEN);
              time(&(entry->updated_time));
            }
            break;
        }
        
      }
      if(entry == NULL){
          printf("Entry not found in routing table, add new entry; metric: %u\n", metric_new);
          sr_add_rt_entry(sr, (struct in_addr){rp_entry->address}, (struct in_addr){ip_hdr->ip_src}, (struct in_addr){rp_entry->mask}, metric_new, interface);
          isUpdated = 1;
      }
    }
    if (isUpdated) {
      printf("Routing table updated, send RIP response\n");
      send_rip_response(sr);
    }
    pthread_mutex_unlock(&(sr->rt_locker));
}