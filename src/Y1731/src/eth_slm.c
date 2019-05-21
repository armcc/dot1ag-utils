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

/*******************************************/
/*                MACRO                    */
/*******************************************/
#define POS_CFM_SLM(s)      (struct y1731_eth_slm *) \
                (CFMHDR_U8((s), sizeof(struct cfmhdr)))
#ifndef UINT_MAX
#define UINT_MAX 4294967295
#endif

/*******************************************/
/*       global variables                  */
/*******************************************/
extern struct oam_entity entity;

/*******************************************/
/*       local operation declaration       */
/*******************************************/
static void add_cfm_common_hdr(uint8_t* buf);

/*******************************************/
/*        local operation define           */
/*******************************************/
static void add_cfm_common_hdr(uint8_t* buf)
{
    cfm_add_hdr(entity.meg_level, 0, CFM_TLVOFFSET_SLM, CFM_OPCODE_SLM, buf);
}

/*******************************************/
/*        operation define                 */
/*******************************************/

/**************************************************************************/
/*! \fn y1731_create_eth_slm(uint8_t *slm_buf, uint8_t* tgt_MAC)
**************************************************************************
*  \brief create ETH-SLM PDU and update database to the targeting entity
*         if the targeting entity does not exist in database, one will be
*         created based on the target MAC address.
*  \param[in] tgt_MAC  - targeting entity MAC address
*  \param[out] slm_buf - buffer address after Ethernet header
*  \return int 1 (success) or 0 (fail)
*/
int32_t y1731_create_eth_slm(uint8_t *slm_buf,
                             uint8_t* tgt_MAC)
{
    int32_t pkt_length = 0;

    if ((NULL == slm_buf) || (NULL == tgt_MAC))
    {
        return 0;
    }

    add_cfm_common_hdr(slm_buf);
    struct y1731_eth_slm * eth_slm = (struct y1731_eth_slm *)
                                        (slm_buf +  sizeof(struct cfmhdr));
    pkt_length += sizeof(struct cfmhdr);

    memset(eth_slm, 0, sizeof(struct y1731_eth_slm));
    memset(&eth_slm->res_rsp_mepid, 0, sizeof(eth_slm->res_rsp_mepid));
    eth_slm->src_mepid = htons(entity.mep_id);
    eth_slm->test_id   = htonl(entity.slm_test_id);

    struct oam_entity_info *entity_db = oam_find_entity_by_mac(tgt_MAC);
    if (NULL == entity_db)
    {
        struct oam_entity_info new_set;
        memset(&new_set, 0, sizeof(new_set));
        memcpy(new_set.info.mac, tgt_MAC, ETH_MAC_HDR_LENGTH);
        new_set.info.tx_FCl = 1;
        new_set.info.first_tx_FCf = 0;
        new_set.info.first_tx_FCb = 0;
        gettimeofday(&new_set.info.slm_tx_time, NULL);
        new_set.info.start_measurement = 1;
        if (NULL == (entity_db = oam_insert_entity(&new_set)))
        {
           fprintf(stderr, "%s :: cannot add new entity; \
                   discard the message\n", __func__);
           return 0;
        }
    }
    else{
        if (0 == entity_db->info.start_measurement) {
            entity_db->info.start_measurement = 1;
            gettimeofday(&entity_db->info.slm_tx_time, NULL);
            entity_db->info.start_rx_FCl = entity_db->info.rx_FCl;
        }
    }

    eth_slm->txFCf = htonl(entity_db->info.tx_FCl);
    pkt_length += sizeof (struct y1731_eth_slm);

    /* Type */
    *(uint8_t *)(slm_buf + pkt_length) = TLV_SENDER_ID;
    pkt_length += sizeof(uint8_t);
    /* minimal length of 1 */
    *(uint16_t *)(slm_buf + pkt_length) = htons(1);
    pkt_length += sizeof(uint16_t);
    /* Chassis ID Length is 0 (no Chassis ID present) */
    *(uint8_t *)(slm_buf + pkt_length) = 0;
    pkt_length += sizeof(uint8_t);

    /* end packet with End TLV field */
    *(uint8_t *)(slm_buf + pkt_length) = htons(TLV_END);
    pkt_length += sizeof(uint8_t);
    return pkt_length;
}

/**************************************************************************/
/*! \fn y1731_process_slm(char *ifname, uint8_t *slm_frame)
**************************************************************************
*  \brief process the ETH-SLM requesting message and reply with an
*         ETH-SLR replying message
*  \param[in] ifname  - message traffic interface
*  \param[out] slm_frame - ETH-SLM buffer including Ethernet header
*  \return int 1 (success) or 0 (fail)
*/
int32_t y1731_process_slm(char *ifname, uint8_t *slm_frame) {

    uint8_t  local_mac[ETHER_ADDR_LEN],
             md_level = 0,
             outbuf[ETHER_MAX_LEN];
    uint16_t vlan;
    int32_t  pktsize = 0,
             size = 0;
    struct   cfmhdr *cfmhdr;
    struct   cfmencap *encap;
    struct   ether_header *slm_ehdr;
    struct   y1731_eth_slm *cfm_slm;

    if ((NULL == ifname) || (NULL == slm_frame)) {
        return 0;
    }

    if (1 != get_local_mac(ifname, local_mac)) {
        fprintf(stderr, "%s :: Cannot determine local MAC address\n", __func__);
        return 0;
    }
    slm_ehdr = (struct ether_header *) slm_frame;

    /* silently discard frame if it was sent by us */
    if (ETHER_IS_EQUAL(slm_ehdr->ether_shost, local_mac)) {
        return 0;
    }

    /* silently discard frame if the SLM destination MAC does not match to the
       receiver's MAC address */
    if (!ETHER_IS_EQUAL(slm_ehdr->ether_dhost, local_mac)) {
        return 0;
    }

    encap = (struct cfmencap *) slm_frame;
    if (IS_TAGGED(slm_frame)) {
        vlan = ntohs(encap->tci) & 0x0fff;
    } else {
        vlan = 0;
    }
    cfmhdr = CFMHDR(slm_frame);
    md_level = GET_MD_LEVEL(cfmhdr);

    if (CFM_OPCODE_SLM != cfmhdr->opcode) {
        fprintf(stderr,"%s :: PDU is not ETH_SLM\n", __func__);
        return 0;
    }
    /* copy fields from SLM PDU */
    cfm_slm = POS_CFM_SLM(slm_frame);

    struct oam_entity_info* entity_db = NULL;
    if (NULL == (entity_db = oam_find_entity_by_mac(slm_ehdr->ether_shost))) {
        struct oam_entity_info new_set;
        memset(&new_set, 0, sizeof(new_set));
        memcpy(new_set.info.mac, slm_ehdr->ether_shost, ETH_MAC_HDR_LENGTH);
        new_set.info.mep_id = ntohs(cfm_slm->src_mepid);
        new_set.info.meg_level = md_level;
        new_set.info.rx_FCl = 1;
        if ((entity_db = oam_insert_entity(&new_set)) == NULL) {
            fprintf(stderr,"%s :: cannot add new entity; discard the message\n", __func__);
            return 0;
        }
    }
    else {
        if (UINT_MAX <= entity_db->info.rx_FCl) {
            entity_db->info.rx_FCl = 1;
            fprintf(stderr, "%s :: RxFCl is larger than Maximum \
                             value of uint32_t, reset to 1\n", __func__);
        }
        else {
            entity_db->info.rx_FCl +=1;
        }
    }

    /*
     * Below the outgoing SLR Ethernet frame is built
     */

    /* clear outgoing packet buffer 'outbuf' */
    memset(outbuf, 0, sizeof(outbuf));

    /* add CFM encapsulation header to packet */
    cfm_add_encap(vlan, local_mac, slm_ehdr->ether_shost, outbuf, &size);
    pktsize += size;

    size = y1731_create_eth_slr(slm_frame+pktsize, outbuf+pktsize, entity_db->info.rx_FCl);
    if (0 >= size)
    {
        fprintf(stderr,"%s :: error creating ETH-SLR\n", __func__);
        return 0;
    }
    pktsize += size;
    if (0 > send_packet(ifname, outbuf, pktsize))	{
        fprintf(stderr, "%s :: send_packet error\n", __func__);
    }
    else {
        if (UINT_MAX <= entity_db->info.tx_FCl) {
            /* FUTURE_DEVELOPMENT: a better way to handle data overflow will be returning
            * an error indicator to user. User can reset the database and repeat the test.*/
            entity_db->info.tx_FCl = 1;
            fprintf(stderr, "%s ::TxFCl is larger than Maxium \
                             value of uint32_t, reset to 1\n", __func__);
        }
        else {
            entity_db->info.tx_FCl += 1;
        }
    }

    return 1;
}
