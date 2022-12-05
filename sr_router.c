/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "vnscommand.h"
#include <string.h>
#include "sr_dumper.h"
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */
    uint16_t ethtype = ethertype(packet);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
    struct sr_if *recv_if = sr_get_interface(sr, interface);
    printf("interface: %s\n", interface);

    if (ethtype == ethertype_arp) {
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      uint16_t arp_op = ntohs(arp_hdr->ar_op);
      if (arp_op == arp_op_request) {
        printf("Got ARP request \n");
        struct sr_arpreq *cache_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

        if (cache_req != NULL) {
          struct sr_packet* pack_it = cache_req->packets;
          while(pack_it != NULL) {
            printf("Sending out cached ARP packets \n");
            /* Add in new ethernet header */
            sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)(pack_it->buf);

            memcpy(eth_header->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            int err = sr_send_packet(sr, pack_it->buf, pack_it->len, pack_it->iface);
            if (err) {
              fprintf(stderr, "Error sending packet: %d\n", arp_op);
            }
            pack_it = pack_it->next;
          }
          sr_arpreq_destroy(&sr->cache, cache_req);
        }
        /* look up outgoing interface */

        struct sr_if* tgt_if = sr->if_list;
        while(tgt_if != NULL) {
          if (tgt_if->ip == arp_hdr->ar_tip) {
            break;
          }
          tgt_if = tgt_if->next;
        }

        uint8_t *arp_resp_hdr = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        sr_ethernet_hdr_t *arp_resp_eth_hdr = (sr_ethernet_hdr_t *)arp_resp_hdr;
        arp_resp_eth_hdr->ether_type = htons(ethertype_arp);
        memcpy(arp_resp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(arp_resp_eth_hdr->ether_shost, recv_if->addr, ETHER_ADDR_LEN);
        print_addr_eth(recv_if->addr);

        sr_arp_hdr_t *arp_resp_arp_hdr = (sr_arp_hdr_t *)(arp_resp_hdr + sizeof(sr_ethernet_hdr_t));
        arp_resp_arp_hdr->ar_op = htons(arp_op_reply);
        arp_resp_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
        arp_resp_arp_hdr->ar_pro = arp_hdr->ar_pro;
        arp_resp_arp_hdr->ar_hln = arp_hdr->ar_hln;
        arp_resp_arp_hdr->ar_pln = arp_hdr->ar_pln;
        memcpy(arp_resp_arp_hdr->ar_sha, tgt_if->addr, ETHER_ADDR_LEN);
        arp_resp_arp_hdr->ar_sip = arp_hdr->ar_tip;
        memcpy(arp_resp_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        arp_resp_arp_hdr->ar_tip = arp_hdr->ar_sip;

        /* printf("Sending packet with size %d \n", (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))); */

        /* Send ARP response */
        int err = sr_send_packet(sr, arp_resp_hdr, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
        free(arp_resp_hdr);
        sr_arpreq_destroy(&(sr->cache), cache_req);

        if (err) {
          fprintf(stderr, "Error sending packet: %d\n", arp_op);
        }


      } else if (arp_op == arp_op_reply) {
        printf("Got ARP reply \n");
        struct sr_arpreq *cache_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (cache_req != NULL) {
          struct sr_packet* pack_it = cache_req->packets;
          while(pack_it != NULL) {
            printf("Sending out cached ARP packets \n");
            /* Add in new ethernet header */
            sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pack_it->buf);
            memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            int err = sr_send_packet(sr, pack_it->buf, pack_it->len, pack_it->iface);
            if (err) {
              fprintf(stderr, "Error sending packet: %d\n", arp_op);
            }
            pack_it = pack_it->next;
          }
          sr_arpreq_destroy(&sr->cache, cache_req);
        }
      } else {
        fprintf(stderr, "Sending error: %d\n", arp_op);
      }
    } else if (ethtype == ethertype_ip) {
      printf("Got IP packet \n");
      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      /* Verify checksum */
      uint16_t chk = cksum((uint8_t *)ip_hdr, sizeof(sr_ip_hdr_t));
      if (chk != 0 && chk != 0xFFFF) {
        fprintf(stderr, "Bad checksum: %d\n", chk);
        return;
      }

      /* Check if ip_dst is a broadcast ip */
      printf("IP dst: %x \n", ip_hdr->ip_dst);
      if (ip_hdr->ip_dst == htonl(0xFFFFFFFF)) {
        printf("Got broadcast IP packet \n");
        /* Check if UDP */
        printf("IP protocol: %x \n", ip_hdr->ip_p);
        if (ip_hdr->ip_p == ip_protocol_udp) {
          printf("Got UDP packet \n");
          sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          /* Check if src port is 520 and dst port is 520 */
          printf("UDP src port and dst port: %d, %d \n", udp_hdr->port_src, udp_hdr->port_dst);
          if (udp_hdr->port_src == htons(520) && udp_hdr->port_dst == htons(520)) {
            printf("Got RIP packet \n");
            sr_rip_pkt_t *rip_hdr = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
            /* Check if RIP request */
            if (rip_hdr->command == 1) {
              printf("Got RIP request \n");
              /* Send RIP response */
              /* TODO:  check if params are correct */
              send_rip_response(sr);
            } else if (rip_hdr->command == 2) {
              printf("Got RIP response \n");
              /* Update routing table */
              /* TODO:  check if params are correct */
              update_route_table(sr, packet, len, interface);
            }
          } else {
            /* Send ICMP port unreachable */
            uint8_t* icmp_err_reply = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_err_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_icmp_hdr->icmp_type = 3;
            reply_icmp_hdr->icmp_code = 3;
            int i;
            for (i = 0; i < ICMP_DATA_SIZE; i++) {
              reply_icmp_hdr->data[i] = *((uint8_t *)(ip_hdr) + i);
            }
            reply_icmp_hdr->icmp_sum = 0;
            reply_icmp_hdr->icmp_sum = cksum((uint8_t *)reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
            sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t *)(icmp_err_reply + sizeof(sr_ethernet_hdr_t));
            reply_ip_hdr->ip_v = 4;
            reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
            reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            reply_ip_hdr->ip_src = recv_if->ip;
            reply_ip_hdr->ip_dst = ip_hdr->ip_src;
            reply_ip_hdr->ip_id = ip_hdr->ip_id;
            reply_ip_hdr->ip_off = ip_hdr->ip_off;
            reply_ip_hdr->ip_ttl = 100;
            reply_ip_hdr->ip_p = ip_protocol_icmp;
            reply_ip_hdr->ip_sum = 0;
            reply_ip_hdr->ip_sum = cksum((uint8_t *)reply_ip_hdr, sizeof(sr_ip_hdr_t));

            sr_ethernet_hdr_t* reply_eth_hdr = (sr_ethernet_hdr_t *)(icmp_err_reply);
            reply_eth_hdr->ether_type = htons(ethertype_ip);
            memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(reply_eth_hdr->ether_shost, recv_if->addr, ETHER_ADDR_LEN);
            print_addr_eth(recv_if->addr);

            int err = sr_send_packet(sr, icmp_err_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
            if (err) {
              fprintf(stderr, "Error sending packet: %d\n", err);
            }
            free(icmp_err_reply);
          }
        }
      } else {
        /* Check all destination IPs */
        struct sr_if* tgt_if = sr->if_list;
        while(tgt_if != NULL) {
          printf("Checking interfaces %s...\n", tgt_if->name);
          print_addr_ip_int(tgt_if->ip);
          print_addr_eth(tgt_if->addr);
          if (tgt_if->ip == ip_hdr->ip_dst) {
            break;
          }
          tgt_if = tgt_if->next;
        }
        
        /* Check if IP packet is for router */
        if (tgt_if != NULL ) {
          printf("Packet is for me \n");
          /* Check if dst interface status is up */
          uint32_t status = sr_obtain_interface_status(sr, tgt_if->name);
          printf("Destination Interface status %s: %d \n", tgt_if->name, status);
          if (status == 1 && ip_hdr->ip_p == ip_protocol_icmp) {
            /* Get ICMP header */
            printf("Got ICMP header \n");
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            /* Ignore anything that isn't an ECHO request */
            if (icmp_hdr->icmp_type != 8 || icmp_hdr->icmp_code != 0) {
              fprintf(stderr, "Wrong ICMP header: type %d, code %d\n", icmp_hdr->icmp_type, icmp_hdr->icmp_code);
              return;
            }
            printf("Got ECHO request \n");
            printf("Making new ECHO reply \n");
            /* Make new ECHO reply, copy ECHO message */
            uint8_t* icmp_echo_reply = (uint8_t *)malloc(len);
            int i;
            for (i = 0; i < len; i++) {
              icmp_echo_reply[i] = packet[i];
            }

            /* Serialize ICMP Header */
            printf("Making ICMP header...");
            sr_icmp_hdr_t *reply_icmp_hdr = (sr_icmp_hdr_t *)(icmp_echo_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_icmp_hdr->icmp_type = 0;
            reply_icmp_hdr->icmp_code = 0;
            reply_icmp_hdr->icmp_sum = 0;
            reply_icmp_hdr->icmp_sum = cksum((uint8_t *)reply_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

            /* Serialize IP Header */
            printf("done. \nMaking IP header...");
            sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(icmp_echo_reply + sizeof(sr_ethernet_hdr_t));
            reply_ip_hdr->ip_src = tgt_if->ip;
            reply_ip_hdr->ip_dst = ip_hdr->ip_src;
            reply_ip_hdr->ip_ttl = 64;
            reply_ip_hdr->ip_p = ip_protocol_icmp;
            reply_ip_hdr->ip_tos = 0;
            reply_ip_hdr->ip_sum = 0;
            reply_ip_hdr->ip_sum = cksum((uint8_t *)reply_ip_hdr, sizeof(sr_ip_hdr_t));

            printf("done. \nMaking Ethernet header...");
            /* Check ARP Cache */
            struct sr_arpentry* dest_mac_loopup = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src);
            sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)(icmp_echo_reply);

            if (dest_mac_loopup == NULL) {
              printf("No ARP entry found. \n");
              sr_print_routing_table(sr);
              memset(reply_eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
            }
            else{
              memcpy(reply_eth_hdr->ether_dhost, dest_mac_loopup->mac, ETHER_ADDR_LEN);  
            }
            /* Serialize Ethernet Header */
            reply_eth_hdr->ether_type = htons(ethertype_ip);
            
            memcpy(reply_eth_hdr->ether_shost, recv_if->addr, ETHER_ADDR_LEN);
            printf("done. \n");

            int err = sr_send_packet(sr, icmp_echo_reply, len, recv_if->name);
            if (err) {
              fprintf(stderr, "Error sending packet: %d\n", err);
            }
            free(icmp_echo_reply);
          } else {
            printf("Sending destination port unreachable \n");
            uint8_t* icmp_err_reply = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_err_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_icmp_hdr->icmp_type = 3;
            reply_icmp_hdr->icmp_code = 3;
            int i;
            for (i = 0; i < ICMP_DATA_SIZE; i++) {
              reply_icmp_hdr->data[i] = *((uint8_t *)(ip_hdr) + i);
            }
            reply_icmp_hdr->icmp_sum = 0;
            reply_icmp_hdr->icmp_sum = cksum((uint8_t *)reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
            sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t *)(icmp_err_reply + sizeof(sr_ethernet_hdr_t));
            reply_ip_hdr->ip_v = 4;
            reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
            reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            reply_ip_hdr->ip_src = recv_if->ip;
            reply_ip_hdr->ip_dst = ip_hdr->ip_src;
            reply_ip_hdr->ip_id = ip_hdr->ip_id;
            reply_ip_hdr->ip_off = ip_hdr->ip_off;
            reply_ip_hdr->ip_ttl = 100;
            reply_ip_hdr->ip_p = ip_protocol_icmp;
            reply_ip_hdr->ip_sum = 0;
            reply_ip_hdr->ip_sum = cksum((uint8_t *)reply_ip_hdr, sizeof(sr_ip_hdr_t));

            sr_ethernet_hdr_t* reply_eth_hdr = (sr_ethernet_hdr_t *)(icmp_err_reply);
            reply_eth_hdr->ether_type = htons(ethertype_ip);
            memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(reply_eth_hdr->ether_shost, recv_if->addr, ETHER_ADDR_LEN);
            print_addr_eth(recv_if->addr);

            int err = sr_send_packet(sr, icmp_err_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
            if (err) {
              fprintf(stderr, "Error sending packet: %d\n", err);
            }
            free(icmp_err_reply);
          }
        } else {
        printf("Packet not destined for router. \n");
        printf("TTL: %d\n", ip_hdr->ip_ttl);
        ip_hdr->ip_ttl--;
        /* Check Header TTL */
        if (ip_hdr->ip_ttl == 0) {
          printf("Time to die. \n");
          uint8_t* icmp_err_reply = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
          sr_icmp_t11_hdr_t* reply_icmp_hdr = (sr_icmp_t11_hdr_t *)(icmp_err_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          reply_icmp_hdr->icmp_type = 11;
          reply_icmp_hdr->icmp_code = 0;
          int i;
          for (i = 0; i < ICMP_DATA_SIZE; i++) {
            reply_icmp_hdr->data[i] = *((uint8_t *)(ip_hdr) + i);
          }
          reply_icmp_hdr->unused = 0;
          reply_icmp_hdr->icmp_sum = 0;
          reply_icmp_hdr->icmp_sum = cksum((uint8_t *)reply_icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

          sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t *)(icmp_err_reply + sizeof(sr_ethernet_hdr_t));
          reply_ip_hdr->ip_v = 4;
          reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
          reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
          reply_ip_hdr->ip_src = recv_if->ip;
          reply_ip_hdr->ip_dst = ip_hdr->ip_src;
          reply_ip_hdr->ip_id = ip_hdr->ip_id;
          reply_ip_hdr->ip_off = htons(IP_DF);
          reply_ip_hdr->ip_ttl = 100;
          reply_ip_hdr->ip_p = ip_protocol_icmp;
          reply_ip_hdr->ip_sum = 0;
          reply_ip_hdr->ip_sum = cksum((uint8_t *)reply_ip_hdr, sizeof(sr_ip_hdr_t));

          sr_ethernet_hdr_t* reply_eth_hdr = (sr_ethernet_hdr_t *)(icmp_err_reply);
          reply_eth_hdr->ether_type = htons(ethertype_ip);
          memcpy(reply_eth_hdr->ether_shost, recv_if->addr, ETHER_ADDR_LEN);
          memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
          print_addr_eth(recv_if->addr);
          int err = sr_send_packet(sr, icmp_err_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t), recv_if->name);
          if (err) {
            fprintf(stderr, "Error sending packet: %d\n", err);
          }
          printf("Sent! \n");
          free(icmp_err_reply);
        } else {
          printf("Finding Longest Prefix Match\n");

          /* Find Longest Prefix Match of the destination IP in routing table */


          /* Check for destination in routing table */
          struct sr_rt* tgt_rt = NULL;
          struct sr_rt* sch_rt = sr->routing_table;
          while (sch_rt != NULL) {
            if (sch_rt->metric >= INFINITY) {
              sch_rt = sch_rt->next;
              continue;
            }
            if ((sch_rt->dest.s_addr & sch_rt->mask.s_addr) == (ip_hdr->ip_dst & sch_rt->mask.s_addr)) {
              printf("Found in routing table\n");
              if (tgt_rt == NULL) {
                tgt_rt = sch_rt;
              } else {
                /* Check for longest prefix match */
                
                struct sr_if* this_if = sr_get_interface(sr, sch_rt->interface);
                struct sr_if* best_if = sr_get_interface(sr, tgt_rt->interface);
                uint32_t this_matches = min(this_if->mask, ~(this_if->mask ^ ip_hdr->ip_dst));
                uint32_t best_matches = min(best_if->mask, ~(best_if->mask ^ ip_hdr->ip_dst));
                if (this_matches > best_matches) {
                  tgt_rt = sch_rt;
                }
              }
            } 
            sch_rt = sch_rt->next;
          }

          uint32_t status = 0;
          if (tgt_rt != NULL) {
            status = sr_obtain_interface_status(sr, tgt_rt->interface);
          } 
          printf("Outgoing Interface status: %d\n", status);
          sr_print_routing_table(sr);
          if (tgt_rt == NULL || status == 0) {
            /* Couldn't find destination */
            /* Send Destination Net Unreachable */
            printf("Sending destination net unreachable. \n");
            uint8_t* icmp_err_reply = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_err_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_icmp_hdr->icmp_type = 3;
            reply_icmp_hdr->icmp_code = 0;
            int i;
            for (i = 0; i < ICMP_DATA_SIZE; i++) {
              reply_icmp_hdr->data[i] = *((uint8_t *)(ip_hdr) + i);
            }
            reply_icmp_hdr->icmp_sum = 0;
            reply_icmp_hdr->icmp_sum = cksum((uint8_t *)reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
            sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t *)(icmp_err_reply + sizeof(sr_ethernet_hdr_t));
            reply_ip_hdr->ip_v = 4;
            reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
            reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            reply_ip_hdr->ip_src = recv_if->ip;
            reply_ip_hdr->ip_dst = ip_hdr->ip_src;
            reply_ip_hdr->ip_id = ip_hdr->ip_id;
            reply_ip_hdr->ip_off = htons(IP_DF);
            reply_ip_hdr->ip_ttl = 100;
            reply_ip_hdr->ip_p = ip_protocol_icmp;
            reply_ip_hdr->ip_sum = 0;
            reply_ip_hdr->ip_sum = cksum((uint8_t *)reply_ip_hdr, sizeof(sr_ip_hdr_t));

            struct sr_arpentry* dest_mac_lookup = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src);
            sr_ethernet_hdr_t* reply_eth_hdr = (sr_ethernet_hdr_t *)(icmp_err_reply);
            if(dest_mac_lookup == NULL){
              printf("Destination MAC not found in cache. \n");
              sr_print_routing_table(sr);
              memset(reply_eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
            }else{
              printf("Destination MAC found in cache. \n");
              memcpy(reply_eth_hdr->ether_dhost, dest_mac_lookup->mac, ETHER_ADDR_LEN);
            }
            
            reply_eth_hdr->ether_type = htons(ethertype_ip);
            memcpy(reply_eth_hdr->ether_shost, recv_if->addr, ETHER_ADDR_LEN);

            int err = sr_send_packet(sr, icmp_err_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
            if (err) {
              fprintf(stderr, "Error sending packet: %d\n", err);
            }
            printf("Sent! \n");
            free(icmp_err_reply);
          } else {
            /* TODO: lab3 update forwarding logic */
            /* Found destination */
            struct sr_if* tgt_if = sr_get_interface(sr, tgt_rt->interface);
            printf("Found destination, sending from interface %s. \n", tgt_if->name);
            uint8_t* packet_forward = (uint8_t *)malloc(len);
            int i;
            for (i = 0; i < len; i++) {
              packet_forward[i] = packet[i];
            }

            sr_ip_hdr_t* fwd_ip_hdr = (sr_ip_hdr_t *)(packet_forward + sizeof(sr_ethernet_hdr_t));
            fwd_ip_hdr->ip_sum += 1;
            printf("IP destination: \n");
            print_addr_ip_int(ntohl(ip_hdr->ip_dst));
            struct sr_arpentry* dest_mac_lookup;
            if(tgt_rt->gw.s_addr != 0){
              dest_mac_lookup = sr_arpcache_lookup(&sr->cache, tgt_rt->gw.s_addr);
              printf("Target has nonzero gateway in routing table. Gateway address: \n");
              print_addr_ip_int(ntohl(tgt_rt->gw.s_addr));
            }
            else{
              dest_mac_lookup = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
              printf("Target is on this network. Target IP: ");
              print_addr_ip_int(ip_hdr->ip_dst);
            }
            sr_ethernet_hdr_t* fwd_eth_hdr = (sr_ethernet_hdr_t *)(packet_forward);
            fwd_eth_hdr->ether_type = htons(ethertype_ip);
            memcpy(fwd_eth_hdr->ether_shost, tgt_if->addr, ETHER_ADDR_LEN);
            if (dest_mac_lookup == NULL) {
              /* couldn't find MAC, send ARP request and cache */
              printf("Couldn't find MAC, caching and sending ARP request. \n");
              if(tgt_rt->gw.s_addr != 0){
                printf("Target has nonzero gateway in routing table. Gateway address: \n");
                print_addr_ip_int(ntohl(tgt_rt->gw.s_addr));
                sr_arpcache_queuereq(&sr->cache, tgt_rt->gw.s_addr, packet_forward, len, tgt_if->name);
              }
              else{
                printf("Target is on this network. Target IP: ");
                print_addr_ip_int(ip_hdr->ip_dst);
                sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet_forward, len, tgt_if->name);
              }
              unsigned char broadcast[ETHER_ADDR_LEN];
              unsigned char unknown[ETHER_ADDR_LEN];
              int i;
              for (i = 0; i < ETHER_ADDR_LEN; i++) {
                broadcast[i] = 0xff;
                unknown[i] = 0x00;
              }
              uint8_t* arp_req = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
              printf("%p\n", arp_req);
              sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(arp_req + sizeof(sr_ethernet_hdr_t));
              arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
              arp_hdr->ar_pro = htons(ethertype_ip);
              arp_hdr->ar_hln = ETHER_ADDR_LEN;
              arp_hdr->ar_pln = 4;
              arp_hdr->ar_op = htons(arp_op_request);
              arp_hdr->ar_sip = tgt_if->ip;
              memcpy(arp_hdr->ar_sha, tgt_if->addr, ETHER_ADDR_LEN);
              if(tgt_rt->gw.s_addr != 0){
                printf("Target has nonzero gateway in routing table. Requesting gateway MAC address\n");
                arp_hdr->ar_tip = tgt_rt->gw.s_addr;
              }
              else{
                printf("Target is on this network. Requesting target MAC address\n");
                arp_hdr->ar_tip = ip_hdr->ip_dst;
              }
              memcpy(arp_hdr->ar_tha, unknown, ETHER_ADDR_LEN);

              sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t *)(arp_req);
              eth_hdr->ether_type = htons(ethertype_arp);
              memcpy(eth_hdr->ether_shost, tgt_if->addr, ETHER_ADDR_LEN);
              memcpy(eth_hdr->ether_dhost, broadcast, ETHER_ADDR_LEN);

              int err = sr_send_packet(sr, arp_req, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), tgt_if->name);
              if (err) {
                fprintf(stderr, "Error sending packet: %d\n", err);
              }
              
              free(arp_req);
            } else {
              printf("Found destination MAC, sending...");
              memcpy(fwd_eth_hdr->ether_dhost, dest_mac_lookup->mac, ETHER_ADDR_LEN);
              int err = sr_send_packet(sr, packet_forward, len, tgt_rt->interface);
              if (err) {
                fprintf(stderr, "Error sending packet: %d\n", err);
              }
              printf("Sent! \n");
              free(packet_forward);
            }
          }
        }
      }
      }
    } else {
      fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    }
}
