/*
 * Copyright (c) 2011~2015
 * Author: Ronald van der Pol
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>

#include "ieee8021ag.h"
#include "dot1ag_eth.h"

#include "oam_entity.h"

#define TX_INTERVAL      2  /* interval to send a LTM */
#define TIMEOUT_INTERVAL 5  /* timeout of LTR */
#define MAX_TTL       30    /* probe until TTL 30 */

static void
usage(void);

static int next_ltm = 0;
static int got_reply = 0;
struct oam_entity entity;
int msg_count = 1;

static void
timeout_handler(int sig) {
    next_ltm = 1;
}


int
main(int argc, char **argv) {
    int ch, i;
    int num_byte;
    char *ifname = NULL;
    uint8_t flags = 0;
    uint8_t md_level = 0;
    uint16_t vlan = 0;
    char *target;
    uint8_t ea[ETHER_ADDR_LEN];
    uint8_t sndbuf[ETHER_MAX_LEN];
    int pktsize = 0;
    int size = 0;
    int sockFD = 0;
    uint8_t localmac[ETHER_ADDR_LEN];
    uint8_t target_mac[ETHER_ADDR_LEN];
    uint8_t LTM_mac[ETHER_ADDR_LEN];
    uint8_t ttl = 1;
    uint32_t transid;
    int hit_target = 0;
    uint8_t buf[ETHER_MAX_LEN];
    struct itimerval tval;
    struct sigaction act;
    struct timeval now, time_sent;
    uint8_t msg_send = 0;
    memset(&entity, 0, sizeof(entity));
    uint8_t with_MAC = 0;
    /* parse command line options */
    while ((ch = getopt(argc, argv, "hi:l:v:c:")) != -1) {
        switch(ch) {
        case 'h':
            usage();
            break;
        case 'i':
            ifname = optarg;
            break;
        case 'l':
            md_level = atoi(optarg);
            break;
        case 'v':
            vlan = atoi(optarg);
            break;
        case 'c':
            msg_count = atoi(optarg);
            break;
        case '?':
        default:
            usage();
        }
    }

    if ( (argc - optind != 1) && (argc - optind != 0) )
    {
        usage();
    }

    /* check for mandatory '-i' flag */
    if (ifname == NULL) {
        usage();
    }

    /* final command line argument is Ethernet address to ethtrace */
    target = argv[argc-1];
    if (argc - optind == 1) {
        if (eth_addr_parse(target_mac, target) != 0) {
            usage();
        }
        else {
            with_MAC = 1;
        }
    }
    else {
        with_MAC = 0;
    }
    /* command line argument parsing finished */

    /* set LTM Group Destination MAC address */
    (void) eth_addr_parse(LTM_mac, ETHER_CFM_GROUP);
    LTM_mac[5] = 0x30 + ((md_level + 8) & 0x0F);

    if (!with_MAC) {
        memcpy(target_mac, LTM_mac, sizeof(target_mac));
    }
    /* seed random generator */
    srandom(time(0));
    /* initialize transaction ID with random value */
    transid = random();

    memset(sndbuf, 0, sizeof(sndbuf));

    if (get_local_mac(ifname, ea) < 0) {
        perror(ifname);
        exit(EXIT_FAILURE);
    }

    printf("Sending CFM LTM probe to ");
    eaprint(target_mac);
    if (with_MAC) {
        printf("\n");
    } else {
        printf(" (GROUP_MAC_ADDRESS)\n");
    }
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        localmac[i] = ea[i];
    }

    /* add CFM encapsulation header to packet */
    if (with_MAC) {
        cfm_add_encap(vlan, localmac, target_mac, sndbuf, &size);
    }
    else {
        cfm_add_encap(vlan, localmac, LTM_mac, sndbuf, &size);
    }
    pktsize += size;
    
    /* add CFM common header to packet */
    flags |= DOT1AG_LTFLAGS_USEFDBONLY;
    cfm_add_hdr(md_level, flags, FIRST_TLV_LTM, CFM_OPCODE_LTM, sndbuf + pktsize);
    pktsize += sizeof(struct cfmhdr);

    cfm_add_ltm(transid, ttl, localmac, target_mac, sndbuf + pktsize);
    pktsize += sizeof(struct cfm_ltm);

    /*
     *  finally add LTM Egress Identifier TLV
     */

    /* XXX code below needs cleanup */
    /* Type */
    *(uint8_t *)(sndbuf + pktsize) = (uint8_t) TLV_LTM_EGRESS_IDENTIFIER;
    pktsize += sizeof(uint8_t);
    /* Egress Identifier is 8 octets */
    *(uint16_t *)(sndbuf + pktsize) = htons(8);
    pktsize += sizeof(uint16_t);
    /* add Unique Identifier (set to 0) */
    *(uint16_t *)(sndbuf + pktsize) = htons(0);
    pktsize += sizeof(uint16_t);
    /* copy MAC address to low-order 6 octets */
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        *(sndbuf + pktsize + i) = localmac[i];
    }
    pktsize += ETHER_ADDR_LEN;

    /* end packet with End TLV field */
    *(uint8_t *)(sndbuf + pktsize) = htons(TLV_END);
    pktsize += sizeof(uint8_t);

    /* open device for listening */
    if (1 != open_listen_socket_raw(&sockFD, ifname)) {
        perror("socket open failed\n");
        exit(EXIT_FAILURE);
    }

    /* define signal handler */
    act.sa_handler = &timeout_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(SIGALRM, &act, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    /* set timer to TX_INTERVAL seconds */
    tval.it_interval.tv_usec = 0;
    tval.it_interval.tv_sec = TX_INTERVAL;
    tval.it_value.tv_usec = 0;
    tval.it_value.tv_sec = TX_INTERVAL;
    if (setitimer(ITIMER_REAL, &tval, NULL) < 0) {
        perror("setitimer");
        exit(EXIT_FAILURE);
    }
    memset(&time_sent, 0, sizeof(time_sent));
    memset(&now, 0, sizeof(now));
    /* start while loop with sending of 1st LTM */
    next_ltm = 1;
    ttl = 0;
    got_reply = 1;

    while (1) {
        if (next_ltm) {
	    if (0 >= msg_count) {
                exit(EXIT_SUCCESS);
            }
            if (!got_reply) {
                (void)gettimeofday(&now,NULL);
                if ((msg_send) && ((now.tv_sec - time_sent.tv_sec) > TIMEOUT_INTERVAL)) {
                    fprintf(stderr, "no replies for LTM %d", transid);
                    fprintf(stderr,", %.3f ms\n", (now.tv_sec - time_sent.tv_sec) * 1000 +
                                          (now.tv_usec - time_sent.tv_usec) / 1000.0);
                    msg_send = 0;
                    msg_count++;
                }
            }
            got_reply = 0;
            /* send next LTM with TTL + 1 */
            if (!msg_send) {
                transid++;
                ttl++;
                if (ttl > MAX_TTL) {
                    exit(EXIT_FAILURE);
                }
                cfm_ltm_set_ttl(ttl, sndbuf);
                cfm_ltm_set_transid(transid, sndbuf);
                if (send_packet(ifname, sndbuf, pktsize) < 0) {
                    fprintf(stderr, "send_packet failed\n");
                    exit(EXIT_FAILURE);
                }
                --msg_count;
                msg_send = 1;
                printf("ttl %d: LTM with id %d\n", ttl, transid);
                next_ltm = 0;
                /* time_sent is time LTM was sent, set it to NOW */
                (void) gettimeofday(&time_sent, NULL);
            }
        }

        if (1 == receive_msg(&sockFD, buf, sizeof(buf), &num_byte)) {
            struct cfmhdr* cfmhdr = CFMHDR(buf);
            switch (cfmhdr->opcode) {
            case CFM_OPCODE_LTR:
                if (cfm_match_ltr(buf, localmac, vlan,
                    md_level, transid, &hit_target)) {
                    print_ltr(buf);
                    got_reply = 1;
                    ttl = 0;
                    msg_send  = 0;
                }
                if ((hit_target) && (0 >= msg_count)) {
                    exit(EXIT_SUCCESS);
                } else if (hit_target) {
                    hit_target = 0;
                }
                break;
            default:
                break;
            }
        }
    }
    return 0;
}


static void
usage() {
    fprintf(stderr, "usage: ethtrace -i interface [-v vlan] [-l mdlevel] [-c # loop] "
                "address\n");
    exit(EXIT_FAILURE);
}
