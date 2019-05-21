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

#define TX_INTERVAL 1 /* send a LBM every second */
#define TIMEOUT_INTERVAL 5 /* timeout for not receiving LTR */
/* incremented by 1 for each Loopback Message transmission */
static uint32_t nextLBMtransID;
static int transIDpos = 0;
int next_lbm = 0;
int got_reply = 0;
int count = 5;    /* default is to send five LBMs */
struct oam_entity entity;

static void
usage();


static void
timeout_handler(int sig) {
    next_lbm = 1;
    nextLBMtransID++;
}

int
main(int argc, char **argv) {
    int ch;
    char *ifname = NULL;
    uint8_t md_level = 0;
    uint16_t vlan = 0;
    char *target;
    uint8_t outbuf[ETHER_MAX_LEN];
    int pktsize = 0;
    int size = 0;
    uint8_t localmac[ETHER_ADDR_LEN];
    uint8_t remotemac[ETHER_ADDR_LEN];
    struct timeval time_sent;
    int sockFD = 0;
    uint8_t buf[ETHER_MAX_LEN];
    struct itimerval tval;
    struct sigaction act;
    struct timeval now;
    memset(&entity, 0, sizeof(entity));
    uint8_t msg_send = 0;
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
            count = atoi(optarg);
            break;
        case '?':
        default:
            usage();
        }
    }
    if (argc - optind != 1) {
        usage();
    }

    /* check for mandatory '-i' flag */
    if (ifname == NULL) {
        usage();
    }

    /* final command line argument is Ethernet address to ethping */
    target = argv[optind];
    if (eth_addr_parse(remotemac, target) != 0) {
        usage();
        exit(EXIT_FAILURE);
    }
    /* command line argument parsing finished */

    /* get Ethernet address of outgoing interface */
    if (get_local_mac(ifname, localmac) != 1) {
        perror(ifname);
        exit(EXIT_FAILURE);
    }

    /*
     * Below the outgoing Ethernet frame is built
     */

    /* clear outgoing packet buffer */
    memset(outbuf, 0, sizeof(outbuf));

    /* add CFM encapsulation header to packet */
    cfm_add_encap(vlan, localmac, remotemac, outbuf, &size);
    pktsize += size;
    
    /* add CFM common header to packet */
    cfm_add_hdr(md_level, 0, FIRST_TLV_LBM, CFM_OPCODE_LBM, outbuf + pktsize);
    pktsize += sizeof(struct cfmhdr);

    /* add 4 octet Loopback Transaction Identifier to packet */
    transIDpos = pktsize;
    /* seed random generator */
    srandom(time(0));
    /* initialize transaction ID with random value */
    nextLBMtransID = random();
    *(uint32_t *)(outbuf + pktsize) = htonl(nextLBMtransID);
    pktsize += sizeof(uint32_t);

    /* XXX code below needs cleanup */
    /*
     *  finally add Sender ID TLV
     */

    /* Type */
    *(uint8_t *)(outbuf + pktsize) = TLV_SENDER_ID;
    pktsize += sizeof(uint8_t);
    /* minimal length of 1 */
    *(uint16_t *)(outbuf + pktsize) = htons(1);
    pktsize += sizeof(uint16_t);
    /* Chassis ID Length is 0 (no Chassis ID present) */
    *(uint8_t *)(outbuf + pktsize) = 0;
    pktsize += sizeof(uint8_t);

    /* end packet with End TLV field */
    *(uint8_t *)(outbuf + pktsize) = htons(TLV_END);
    pktsize += sizeof(uint8_t);

    /* Assembled Ethernet frame is 'outbuf', its size is 'pktsize' */

    /* open device for listening */
    if (1 != open_listen_socket_raw(&sockFD, ifname)) {
        perror("socket open failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Sending CFM LBM to %02x:%02x:%02x:%02x:%02x:%02x\n",
        remotemac[0], remotemac[1], remotemac[2],
        remotemac[3], remotemac[4], remotemac[5]);


    /* define signal handler */
    act.sa_handler = &timeout_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(SIGALRM, &act, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    /* set timer to INTERVAL seconds */
    tval.it_interval.tv_usec = 0;
    tval.it_interval.tv_sec = TX_INTERVAL;
    tval.it_value.tv_usec = 0;
    tval.it_value.tv_sec = TX_INTERVAL;
    if (setitimer(ITIMER_REAL, &tval, NULL) < 0) {
        perror("setitimer");
        exit(EXIT_FAILURE);
    }

    /* avoid starting with a request timeout message */
    got_reply = 1;

    while (1) {
        int num_byte;

        if (next_lbm) {
            if (count <= 0) {
                exit(EXIT_SUCCESS);
            }
            if (!got_reply) {
               (void)gettimeofday(&now,NULL);
                if ((msg_send) && ((now.tv_sec - time_sent.tv_sec) > TIMEOUT_INTERVAL)) {
                    printf("Request timeout for %d\n", nextLBMtransID);
                    printf(", %.3f ms\n", (now.tv_sec - time_sent.tv_sec) * 1000 +
                                          (now.tv_usec - time_sent.tv_usec) / 1000.0);
                    msg_send = 0;
                }
            }
            got_reply = 0;
            /* send the next LBM */
        if (!msg_send) {
                if (send_packet(ifname, outbuf, pktsize) < 0) {
                    perror("send_packet");
                    exit(EXIT_FAILURE);
                }
                    
                /* time_sent is time LBM was sent, set it to NOW */
                (void) gettimeofday(&time_sent, NULL);

          //printf("send a LTM with sequence [%d]\n", nextLBMtransID);
                next_lbm = 0;
                msg_send = 1;
                count--;
           }
        }

        if (1 == receive_msg(&sockFD, buf, sizeof(buf), &num_byte)) {
            struct cfmhdr *cfmhdr = CFMHDR(buf);
            switch (cfmhdr->opcode) {
                /*opcode should be 2 for LBR; it is defined in ieee8021ag.h; see IEEE802.1AG spec for detail. */
            case CFM_OPCODE_LBR:
                if (cfm_match_lbr(buf, localmac,
                    remotemac, vlan, md_level,
                    nextLBMtransID)) {
                    printf("%d bytes from ", num_byte);
                    printf("%02x:%02x:%02x:%02x:%02x:%02x",
                        remotemac[0], remotemac[1],
                        remotemac[2], remotemac[3],
                        remotemac[4], remotemac[5]);
                    printf(", sequence %d", nextLBMtransID);
                    (void)gettimeofday(&now, NULL);
                    printf(", %.3f ms\n", (now.tv_sec -
                        time_sent.tv_sec) * 1000 +
                        (now.tv_usec - time_sent.tv_usec) /
                        1000.0);
                    got_reply = 1;
                    msg_send  = 0;
                }
                break;
            default:
                break;
            }
        }
        (void) gettimeofday(&now, NULL);
    }

    exit(EXIT_SUCCESS);
}

static void
usage() {
    fprintf(stderr, "usage: ethping -i interface [-v vlan] [-l mdlevel] "
        "[-c count] address\n");
    exit(EXIT_FAILURE);
}
