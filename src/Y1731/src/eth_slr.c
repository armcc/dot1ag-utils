/*
* Copyright (c) 2015
* Author: Ming-Jye Chang
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
/*FUTURE_DEVELOPMENT: replace bug report from printf to a debug tool, which can be turned on and off via CLI */
/*******************************************/
/*       header files                      */
/*******************************************/
#include "eth_slm.h"
#include "eth_slr.h"
#include <errno.h>
#include "ieee8021ag.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "dot1ag_eth.h"
#include "oam_entity.h"
#include "oam_db.h"
#include <time.h>

/*******************************************/
/*                MACRO                    */
/*******************************************/
#define SLR_TIMEOUT 5 /* mesaurement in second */

#ifndef UINT_MAX
#define UINT_MAX 4294967295
#endif

/*******************************************/
/*       global variables                  */
/*******************************************/
extern struct oam_entity entity;

/*******************************************/
/*        local operation define           */
/*******************************************/

/*******************************************/
/*        operation define                 */
/*******************************************/
/**************************************************************************/
/*! \fn y1731_create_eth_slr(uint8_t *slm_buf,
 *                           uint8_t *slr_buf,
 *                            uint32_t RxFCl)
**************************************************************************
*  \brief create ETH-SLR PDU based on a ETH-SLM request message
*  \param[in] slm_buf - ETH-SLM frame without ethernet header
*  \param[in] slr_buf - ETH-SLR buffer without ethernet header
*  \param[in] RxFC;   - number of ETH-SLR has been received, stored in DB
*  \return int 1 (success) or 0 (fail)
*/
int32_t y1731_create_eth_slr(uint8_t *slm_buf,
                             uint8_t *slr_buf,
                             uint32_t RxFCl)
{
    int32_t length = 0;

    if ((NULL == slm_buf) || (NULL == slr_buf))
    {
        return 0;
    }

    struct cfmhdr *slm_commonHdr  = (struct cfmhdr*) slm_buf;
    struct y1731_eth_slm *eth_slm = (struct y1731_eth_slm*) (slm_buf + sizeof(struct cfmhdr));
    struct cfmhdr *slr_commonHdr  = (struct cfmhdr*) slr_buf;
    struct y1731_eth_slr *eth_slr = (struct y1731_eth_slr*) (slr_buf + sizeof(struct cfmhdr));

    /* fill in the common header section */
    memcpy(slr_commonHdr, slm_commonHdr, sizeof(struct cfmhdr));
    slr_commonHdr->tlv_offset = CFM_TLVOFFSET_SLR;
    slr_commonHdr->opcode = CFM_OPCODE_SLR;
    length += sizeof(struct cfmhdr);

    /* calling ntohs for eth_slm is not necessary since we are
       copying and replying the value in the eth-slr message */
    eth_slr->src_mepid = eth_slm->src_mepid;
    eth_slr->rsp_mepid = htons(entity.mep_id);
    eth_slr->test_id   = eth_slm->test_id;
    eth_slr->txFCf     = eth_slm->txFCf;
    eth_slr->txFCb     = htonl(RxFCl);

    length += sizeof(struct y1731_eth_slr);
    /* end packet with End TLV field */
    *(uint8_t *)(slr_buf + length) = htons(TLV_END);
    length += sizeof(uint8_t);

    return length;
}

/**************************************************************************/
/*! \fn y1731_process_slr(char *ifname, uint8_t *slr_frame)
**************************************************************************
*  \brief processing the received ETH-SLR message, store the data into DB
*         when measurement period expired, it will calculate the far/near
*         frame loss.
*  \param[in] ifname    - message traffic interface
*  \param[in] slr_frame - ETH-SLR frame with ethernet header
*  \return int 1 (success) or 0 (fail)
*/
int32_t y1731_process_slr(char *ifname, uint8_t *slr_frame)
{
    struct ether_header *slr_ehdr = NULL;
    uint8_t local_mac[ETHER_ADDR_LEN];
    struct cfmhdr *cfmhdr = NULL;
    struct cfmencap *cfmencap = NULL;
    uint8_t md_level = 0;
    struct y1731_eth_slr *cfm_slr = NULL;
    struct timeval recv_time;
    uint16_t resp_mep_id = 0;
    gettimeofday(&recv_time,NULL);

    if ( (NULL == ifname) || (NULL == slr_frame) ){
        fprintf(stderr, "%s :: invalid argument\n", __func__);
        return 0;
    }

    cfmencap = (struct cfmencap *) slr_frame;

    /* Check ethertype */
    if (IS_TAGGED(slr_frame)) {
        if (cfmencap->ethertype != htons(ETYPE_CFM)) {
            return (0);
        }
    } else {
        if (cfmencap->tpid != htons(ETYPE_CFM)) {
            return (0);
        }
    }

    if (get_local_mac(ifname, local_mac) != 1) {
        fprintf(stderr, "%s :: Cannot determine local MAC \
                address\n", __func__);
        return 0;
    }
    slr_ehdr = (struct ether_header *) slr_frame;

    /* silently discard frame if it was sent by us */
    if (ETHER_IS_EQUAL(slr_ehdr->ether_shost, local_mac)) {
        return 0;
    }

    cfmhdr = CFMHDR(slr_frame);
    md_level = GET_MD_LEVEL(cfmhdr);

    if (CFM_OPCODE_SLR != cfmhdr->opcode) {
        fprintf(stderr,"%s :: PDU is not ETH_SLR\n",  __func__);
        return 0;
    }
    /* copy fields from SLM PDU */
    cfm_slr = POS_CFM_SLR(slr_frame);
    resp_mep_id = ntohs(cfm_slr->rsp_mepid);
    if ((resp_mep_id < MIN_MEPID) ||
        (resp_mep_id > MAX_MEPID)) {
        fprintf(stderr, "%s :: resp_mepID is out of range\n", __func__);
        return 0;
    }

    struct oam_entity_info* entity_db = NULL;
    if (NULL == (entity_db = oam_find_entity_by_mac(slr_ehdr->ether_shost))) {
        struct oam_entity_info new_set;
        memset(&new_set, 0, sizeof(new_set));
        memcpy(new_set.info.mac, slr_ehdr->ether_shost, ETH_MAC_HDR_LENGTH);
        new_set.info.mep_id = resp_mep_id;
        new_set.info.meg_level = md_level;
        new_set.info.rx_FCl = 1;
        if ((entity_db = oam_insert_entity(&new_set)) == NULL) {
            fprintf(stderr,"%s :: cannot add new entity; \
                    discard the message\n", __func__);
            return 0;
        }
    }
    else {
        /* FUTURE_DEVELOPMENT: a better way to handle data overflow will be returning
         * an error indicator to user. User can reset the database and repeat the test.*/
        if (UINT_MAX <= entity_db->info.rx_FCl) {
            entity_db->info.rx_FCl = 1;
            fprintf(stderr, "%s :: RxFCl is larger than Maximum \
                             value of uint32_t, reset to 1\n", __func__);
        }
        else {
            entity_db->info.rx_FCl +=1;
        }
    }

    if (0 == entity_db->info.first_slr_received) {
        /* save of the current RxFCl and the first SLR TxFCf/TxFCb */
        entity_db->info.first_slr_received = 1;
        entity_db->info.first_tx_FCf = ntohl(cfm_slr->txFCf);
        entity_db->info.first_tx_FCb = ntohl(cfm_slr->txFCb);
        entity_db->info.start_rx_FCl = entity_db->info.rx_FCl;
        entity_db->info.start_measurement = recv_time.tv_sec;
    }

    /* discard the SLR if received after 5 second */
    uint32_t deltaTime_sec = (uint32_t)(recv_time.tv_sec - entity_db->info.slm_tx_time.tv_sec);
    if (SLR_TIMEOUT < deltaTime_sec) {
        fprintf(stderr,"%s :: ETH-SLR received after timeout\n", __func__);
    }
    else {
        if (entity_db->info.measurement_period <=
            (recv_time.tv_sec - entity_db->info.start_measurement)) {

            int32_t frameLoss_nearEnd = 0,
                     frameLoss_farEnd  = 0;
            int16_t slr_txFCf = ntohl(cfm_slr->txFCf),
                     slr_txFCb = ntohl(cfm_slr->txFCb);

            entity_db->info.start_measurement = 0; /* start measurement */
            entity_db->info.first_slr_received = 0; /* reset to false */
            entity_db->info.measurement_period = 0;
            frameLoss_farEnd = abs(slr_txFCf - entity_db->info.first_tx_FCf) -
                               abs(slr_txFCb - entity_db->info.first_tx_FCb);
            frameLoss_nearEnd = abs(slr_txFCb - entity_db->info.first_tx_FCb) -
                                abs(entity_db->info.rx_FCl - entity_db->info.start_rx_FCl);
            printf("frame loss far end = %d \n frame loss near end =%d\n",
                        frameLoss_farEnd, frameLoss_nearEnd);
        }
    }
    return 1;

}
