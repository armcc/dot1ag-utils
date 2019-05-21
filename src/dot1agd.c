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
/***************************/
/*       HEADER            */
/***************************/
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include "ieee8021ag.h"
#include "dot1ag_eth.h"
#include "eth_slm.h"
#include "eth_slr.h"
#include "oam_entity.h"
#include "oam_db.h"
#include <netinet/ether.h>
#include <net/if.h>
#include <net/if_packet.h>
#include <sys/ioctl.h>

/*FUTURE_DEVELOPMENT:  -increase TxFCl when successive transmit a ETH-SLM request message;
 *                     -set the timer when first ETH-SLM transmitted;
 *                     -record the start time of first ETH-SLM transmitted;
 *                     -set the firstSLRreceived to 0 when send out the first ETH-SLM;
 *                     -set startMeasurement to 1 when send out the first ETH-SLM ;
 *                     -save of RxFCL to startRxFCl when measurement begin;
 *                     -add a timer thread for each MEP, calculate the SL when time up
 *                      even without a SLR msg
 *                     - save the Txtime when send a LBM
 *                     - save the transaction ID of LBM to Database
 */

/***************************/
/*       MACRO             */
/***************************/
#define INTERVAL          1
#define NECESSARY_OPT     0x7f
#define INTERFACE_OPT_BIT 0x1
#define MD_LEVEL_OPT_BIT  0x2
#define MEP_ID_OPT_BIT    0x4
#define LOOPBACK_OPT_BIT  0x8
#define LINKTRACE_OPT_BIT 0x10
#define SLM_OPT_BIT       0x20
#define ENTITY_OPT_BIT    0x40
#define OVERRIDE_MAC_BIT  0x80
#define SA_INDEX_LIST_BIT 0x100
#define SF_INDEX_BIT      0x200

/***************************/
/*       global variable   */
/***************************/
struct oam_entity entity;

#ifdef TIME_OUT_HANDLER /* comment out for phase 1; we might need this in the future*/
static int loop;
#endif

/************************************/
/*  local function declaration      */
/************************************/
static void usage(void);

#ifdef TIME_OUT_HANDLER /* comment out for phase 1; we might need this in the future*/
static void
timeout_handler(int sig) {
 /* this is probably not necessary since we are running as a daemon on background */
//	loop = 0;
}
#endif

int
main(int argc, char **argv) {
    int listenFD     = -1,
        ch           = 0,
        num_byte     = -1,
        entity_type  = (int)MEP;
    char *ifname = NULL;
    char *ptr;
    uint8_t localmac[ETHER_ADDR_LEN],
             i,
             buf[ETHER_MAX_LEN*2];
#ifdef TIME_OUT_HANDLER /* comment out for phase 1; we might need this in the future*/
    struct itimerval tval;
    struct sigaction act;
#endif

    int32_t md_level = -1,
            mep_id   = -1;
    char *domain = NULL,
         *association = NULL;
    uint8_t loopbackEnable  = 0,
            linktraceEnable = 0,
            frameLossEnable = 0,
            overrideMac     = 0;

#ifdef L2VPN_SUPPORT
    uint8_t  sa_index[L2VPN_SA_MAX_NUM];
    uint8_t  sa_index_count     = 0;
    uint8_t  sa_index_filter    = 0;
    uint8_t  sf_index           = 0;
    uint8_t  sf_index_valid     = 0;
#endif
    uint8_t operation_mode = CFM_MODE;

    int argument = NECESSARY_OPT;
    /* parse command line options */
    /* -l = md_level, -m = mep_id, -d = md_name, -a = ma_name,
       -t = linktrace_enable, -b = loopback_enable, -s = synthetic frame loss enable */
    while ((ch = getopt(argc, argv, "hi:l:m:d:a:t:b:s:e:v:o:f:u:p:")) != -1) {
        switch(ch) {
        case 'h':
            usage();
            break;
        case 'i':
            ifname = optarg;
            argument &= (~INTERFACE_OPT_BIT);
            break;
        case 'l':
            md_level = atoi(optarg);
            argument &= (~MD_LEVEL_OPT_BIT);
            break;
        case 'm':
            mep_id = atoi(optarg);
            argument &= (~MEP_ID_OPT_BIT);
            break;
        case 'd':
            domain = optarg;
            optind--; /* optional */
            break;
        case 'a':
            association = optarg;
            optind--; /* optional */
            break;
        case 't':
            linktraceEnable = (atoi(optarg) == 1) ? 1 : 0;
            argument &= (~LINKTRACE_OPT_BIT);
            break;
#ifdef L2VPN_SUPPORT
        case 'f':
            argument &= (~SA_INDEX_LIST_BIT);
            ptr = strtok(optarg, ",");
            while(ptr != NULL){
                    sa_index[sa_index_count] = (uint8_t)atoi(ptr);
                    sa_index_count++;
                    ptr = strtok(NULL, ",");
            }
            sa_index_filter = 1;
            break;

        case 'u':
            sf_index = (atoi(optarg) == 1) ? 1 : 0;
            sf_index_valid = 1;
            argument &= (~SF_INDEX_BIT);
            break;
#endif
        case 'o':
            overrideMac = 1;
            i=0;
            argument &= (~OVERRIDE_MAC_BIT);
            ptr = strtok(optarg, ":");
            while(ptr != NULL){
                    localmac[i] = (uint8_t)strtoul(ptr, NULL, 16);
                    i++;
                    ptr = strtok(NULL, ":");
            }
            if(i != ETHER_ADDR_LEN){
                fprintf(stderr, "Invalid MAC address!\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'b':
            loopbackEnable = (atoi(optarg) == 1) ? 1 : 0;
            argument &= (~LOOPBACK_OPT_BIT);
            break;
        case 's':
            frameLossEnable = (atoi(optarg) == 1) ? 1 : 0;
            argument &= (~SLM_OPT_BIT);
            break;
        case 'e':
            switch (atoi(optarg))
            {
                case 1:
                    entity_type = (int)MEP;
                    break;
                case 2:
                    entity_type = (int)MIP;
                    break;
                default:
                    usage();
                    break;
            }
            argument &= (~ENTITY_OPT_BIT);
            break;
        case 'p':
            switch (atoi(optarg))
            {
                case Y1731_MODE:
                    operation_mode = Y1731_MODE;
                    break;
                case CFM_MODE:
                default:
                    operation_mode = CFM_MODE;
                    fprintf(stderr, "Invalid operation mode, set to CFM_MODE(v2006)\n");
            }
            break;
        case '?':
        default:
            usage();
        }
    }
    if (argument) {
        usage();
    }

    /* check for mandatory '-i' flag */
    if (ifname == NULL) {
        usage();
    }
    /* command line argument parsing finished */

    /* get Ethernet address of outgoing interface */
    if (!overrideMac) {
        if (get_local_mac(ifname, localmac) != 1) {
            perror(ifname);
            exit(EXIT_FAILURE);
        }
    }

    memset(&entity, 0, sizeof(entity));
    /* get the operation_mode (CFM or Y1731) */
    entity.operation_mode = operation_mode;
    entity.if_name = ifname;
    entity.override_mac = overrideMac;
    memcpy(entity.mac, localmac, sizeof(entity.mac));
#ifdef L2VPN_SUPPORT
    entity.sf_index = sf_index;
    entity.sf_index_valid = sf_index_valid;
    entity.sa_index_count = sa_index_count;
    entity.sa_index_filter = sa_index_filter;
    memcpy(entity.sa_index, sa_index, sizeof(uint8_t) * L2VPN_SA_MAX_NUM);
#endif
    entity.mep_mip = entity_type;
    if ( (MAX_MD_LEVEL < md_level ) || (MIN_MD_LEVEL > md_level) )
    {
        fprintf(stderr,"invalid MD Level: 0~7");
        usage();
        exit(EXIT_FAILURE);
    }

    if ((MAX_MEPID < mep_id) || (MIN_MEPID > mep_id))
    {
        fprintf(stderr,"invalid MEP ID: 1~8191");
        usage();
        exit(EXIT_FAILURE);
    }
    entity.meg_level = md_level;
    entity.mep_id    = mep_id;
    if (NULL != association)
    {
        /* FUTURE_DEVELOPMENT: add usage of management association in the future */
    }
    if (NULL != domain)
    {
        /* FUTURE_DEVELOPMENT: add usage of management domain in the future */
    }

    if ((!loopbackEnable) && (!linktraceEnable) && (!frameLossEnable))
    {
        fprintf(stderr,"%s :: no OAM function enabled\n", __func__);
        usage();
        exit(EXIT_FAILURE);
    }

    /* create a listening socket */
    if (1 != open_listen_socket_raw(&listenFD, ifname)) {
        fprintf(stderr, "%s :: dot1agd, listening socket open failed\n", __func__);
        exit(EXIT_FAILURE);
    }

#ifdef TIME_OUT_HANDLER /* comment out for phase 1; we might need this in the future*/
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
    tval.it_interval.tv_sec = 15;
    tval.it_value.tv_usec = 0;
    tval.it_value.tv_sec = 15;
    if (setitimer(ITIMER_REAL, &tval, NULL) < 0) {
        perror("setitimer");
        exit(EXIT_FAILURE);
    }

    loop = 1;
#endif
    /* listen for CFM frames */
    printf("Listening on interface %s for CFM frames\n", ifname);
#ifdef TIME_OUT_HANDLER /* comment out for phase 1; we might need this in the future*/
    while (loop) {
#else
    while(1) {
#endif
        /*
         * Wait for a CFM frames.
         */

        memset(buf, 0, sizeof(buf));
        if (1 == receive_msg(&listenFD, buf, sizeof(buf), &num_byte)) {
            struct cfmhdr* cfmhdr = CFMHDR(buf);
            switch (cfmhdr->opcode) {
                case CFM_OPCODE_CCM:
                    break;
                case CFM_OPCODE_LBM:
                    /* according to y1731- clause 7.2.2; MEP should transmit a unicast
                       frame with ETH-LB reply information after a randomized delay in
                       the range of 0 to 1 second; current design will not generate a
                       random delay due to the fact that the actual processing time has
                       not been benchmarked. The cfm_send_lbr function call might already
                       called with a small amout of delay time.*/

                    if (loopbackEnable)
                    {
                        cfm_send_lbr(ifname, buf, num_byte);
                    }
                    break;
                case CFM_OPCODE_LTM:
                    /* Linktrace Responder */
                    if (linktraceEnable)
                    {
                        process_ltm(ifname, buf);
                    }
                    break;
    #if 0 /* FUTURE_DEVELOPMENT: processing reply messages are not supported now */
                case CFM_OPCODE_LBR:
                    /* Y,1731 cluase 7.2.2.3 : discard the LBR if entity is MIP */
                    if (MEP == entity.mep_mip) {
                        process_lbr(ifname, buf);
                    }
                    break;
                
                case CFM_OPCODE_LTR:
                    process_ltr(ifname, buf);
                    break;
                case CFM_OPCODE_SLR:
                    /* Synthetic Loss Responder */
                    y1731_process_slr(ifname, buf);
                    break;
    #endif
                case CFM_OPCODE_SLM:
                    /* Synthetic Loss Measurement */
                    if (frameLossEnable)
                    {
                        y1731_process_slm(ifname, buf);
                    }
                    break;
                default:
                    break;
            }
        }
    }

    exit(EXIT_SUCCESS);
}

static void
usage() {
    fprintf(stderr, "usage: dot1agd -i interface\n \
              -l md_level\n \
              -m mep_id\n \
              -t linktrace_enable(0:1)\n \
              -b loopback_enable(0:1)\n \
              -s synthetic_frame_loss_enable(0:1)\n \
              -e entity type (1 = MEP, 2 = MIP)\n \
              optional :-d md_name\n \
                        -o mac_address(xx:xx:xx:xx:xx:xx)\n \
                        -a ma_name\n \
                        -p operation_mode(0:1)\n");
#ifdef L2VPN_SUPPORT
    fprintf(stderr, "\  -f sf_index_filter_list (for DOCSIS L2VPN mode)\n \
                        -u upstream_service_flow_index (for DOCSIS L2VPN mode)\n");
#endif
    exit(EXIT_FAILURE);
}
