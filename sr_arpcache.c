#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"
#include "sr_dumper.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    struct sr_arpreq *it = sr->cache.requests;
    struct sr_arpreq *prev = NULL;
    unsigned char broadcast[ETHER_ADDR_LEN];
    unsigned char unkown[ETHER_ADDR_LEN];
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        broadcast[i] = 0xff;
        unkown[i] = 0x00;
    }
    while (it != NULL) {
      if (difftime(time(NULL), it->sent) > 1.0) {
        if (it->times_sent > 4) {
          struct sr_packet *pack_it = it->packets;
          while (pack_it != NULL) {
            sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)pack_it->buf;
            sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(pack_it->buf + sizeof(sr_ethernet_hdr_t));
            struct sr_if *recv_if = sr_get_interface(sr, pack_it->iface);

            printf("Sending destination host unreachable \n");
            uint8_t* icmp_err_reply = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t*)(icmp_err_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_icmp_hdr->icmp_type = 3;
            reply_icmp_hdr->icmp_code = 1;
            int i;
            for (i = 0; i < ICMP_DATA_SIZE; i++) {
              reply_icmp_hdr->data[i] = *((uint8_t*)ip_hdr + i);
            }
            reply_icmp_hdr->icmp_sum = 0;
            reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

            sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t*)(icmp_err_reply + sizeof(sr_ethernet_hdr_t));
            reply_ip_hdr->ip_v = 4;
            reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
            reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            reply_ip_hdr->ip_src = recv_if->ip;
            reply_ip_hdr->ip_dst = ip_hdr->ip_src;
            reply_ip_hdr->ip_id = ip_hdr->ip_id;
            reply_ip_hdr->ip_off = htons(IP_DF);
            reply_ip_hdr->ip_ttl = 100;
            reply_ip_hdr->ip_p = ip_protocol_icmp;
            reply_ip_hdr->ip_sum = 0;
            reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));

            sr_ethernet_hdr_t* reply_eth_hdr = (sr_ethernet_hdr_t*)icmp_err_reply;
            reply_eth_hdr->ether_type = htons(ethertype_ip);
            memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(reply_eth_hdr->ether_shost, recv_if->addr, ETHER_ADDR_LEN);

            int err = sr_send_packet(sr, icmp_err_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), pack_it->iface);
            if (err) {
              fprintf(stderr, "Sedning error: %d\n", err);
            }
            free(icmp_err_reply);
            pack_it = pack_it->next;
          }
          struct sr_arpreq *temp = it;
          it = it->next;
          sr_arpreq_destroy(&(sr->cache), temp); 
        } else {
          printf("Resending ARP request... \n");
          it->times_sent++;
          it->sent = time(NULL);

          /* Find longest prefix match */
          struct sr_rt* tgt_rt = NULL;
          struct sr_rt* sch_rt = sr->routing_table;
          while (sch_rt != NULL) {
            if(sch_rt->metric >= INFINITY){
                sch_rt = sch_rt->next;
                continue;
            }
            if ((sch_rt->dest.s_addr & sch_rt->mask.s_addr) == (it->ip & sch_rt->mask.s_addr)) {
              if (tgt_rt == NULL) {
                printf("Found exact match\n");
                tgt_rt = sch_rt;
              } else {
                struct sr_if* this_if = sr_get_interface(sr, sch_rt->interface);
                struct sr_if* best_if = sr_get_interface(sr, tgt_rt->interface);
                uint32_t this_matches = min(this_if->mask, ~(this_if->ip ^ it->ip));
                uint32_t best_matches = min(best_if->mask, ~(best_if->ip ^ it->ip));
                if (this_matches > best_matches) {
                  tgt_rt = sch_rt;
                }
              }
            }
            sch_rt = sch_rt->next;
          }
          struct sr_if* tgt_if = sr_get_interface(sr, tgt_rt->interface);
          uint8_t* arp_req = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
          sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(arp_req + sizeof(sr_ethernet_hdr_t));
          arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
          arp_hdr->ar_pro = htons(ethertype_ip);
          arp_hdr->ar_hln = ETHER_ADDR_LEN;
          arp_hdr->ar_pln = 4;
          arp_hdr->ar_op = htons(arp_op_request);
          arp_hdr->ar_sip = tgt_if->ip;
          memcpy(arp_hdr->ar_sha, tgt_if->addr, ETHER_ADDR_LEN);
          arp_hdr->ar_tip = it->ip;
          memcpy(arp_hdr->ar_tha, unkown, ETHER_ADDR_LEN);

          sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)arp_req;
          eth_hdr->ether_type = htons(ethertype_arp);
          memcpy(eth_hdr->ether_dhost, broadcast, ETHER_ADDR_LEN);
          memcpy(eth_hdr->ether_shost, tgt_if->addr, ETHER_ADDR_LEN);

          prev = it;
          it = it->next;

        }
      } else {
        prev = it;
        it = it->next;
      }
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = NULL;
        if (req->packets == NULL){
            req->packets = new_pkt;
        }
        else{
            struct sr_packet *p = req->packets;
            while(p->next != NULL)
                p = p->next;
            p->next = new_pkt;
        }
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}
