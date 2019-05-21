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

#ifndef OAM_ENTITY_H
#define OAM_ENTITY_H

/***************************/
/*       HEADER            */
/***************************/
#include <stdint.h>
#include <sys/time.h>
#include "ieee8021ag.h"
#ifdef L2VPN_SUPPORT
#define L2VPN_SA_MAX_NUM 64
#define L2VPN_SF_INDEX_OFFSET 24
#define L2VPN_SF_INDEX_MASK 0xFF000000
#define L2VPN_RELATED_SAID_MASK 0x1F
#endif
#ifdef __cplusplus
extern "C" {
#endif

/***************************/
/*       MACRO             */
/***************************/
    #define ETH_MAC_HDR_LENGTH 6     /* Ethernet header MAC length */
    #define INTERFACE_NAME_LENGTH 6  /* interface name length */
    #define MEG_ID_LENGTH 10 /* MEG ID length */

/***************************/
/*       ENUM              */
/***************************/
    enum ENTITY_TYPE_E {
        MEP = 0,
        MIP = 1,
    };

/***************************/
/*       ADT               */
/***************************/
    /* entity definition */
    struct oam_entity
    {
        enum ENTITY_TYPE_E mep_mip;       /* set entity to MEP or MIP */
        uint16_t mep_id;                  /* entity MEP ID*/
        uint8_t  meg_level;               /* MEG level */
        char     meg_id[MEG_ID_LENGTH];   /* entity MEG_ID */
        uint8_t  mac[ETH_MAC_HDR_LENGTH]; /* MAC address */

#ifdef L2VPN_SUPPORT
        uint8_t  sa_index[L2VPN_SA_MAX_NUM];        /* SA indexes to filter on */
        uint8_t  sa_index_count;                    /* How many SA indexes stored */
        uint8_t  sa_index_filter;                   /* Flag controlling whether to filter by SA index */
        uint8_t  sf_index;                          /* Pre-fetched upstream service flow index */
        uint8_t  sf_index_valid;                    /* Flag setting whether we have upstream SF index */
#endif

        int32_t  if_index;                /* interface index */
        char     *if_name;                /* interface name */

        uint16_t vlan;
        uint8_t  rdi;                     /* RDI flag; error indicator*/
        uint8_t  is_MIP;                  /* set to true if entity is a MIP */
        uint8_t operation_mode;           /* set to CFM mode as default */
        /* LTM specific info */
        struct timeval ltm_tx_time;       /* timestamp when sending a LTM msg */
        /*FUTURE_DEVELOPMENT: transac number in link list */
        /* LBM specific info */
        uint32_t lbm_transactionID;           /* transaction ID sent out from LBM */
        struct   timeval lbm_tx_time;         /* timestamp when sending a LBM msg */
        uint32_t lbm_lbr_mismatch;            /* counter for mismatch LBM/LBR */
        uint8_t  data_tlv[PDU_FRAME_LIMIT+1];  /* data_tlv of last LBM */
        uint8_t  test_pattern_tlv[PDU_FRAME_LIMIT+1]; /*test pattern tlv */
        /* SLM specific info. */
        uint32_t start_measurement;
        uint8_t  first_slr_received;
        int32_t  measurement_period;    /* measurement period */
        struct timeval slm_tx_time;    /* timestamp when sending a SLM msg */
        uint32_t first_tx_FCf;           /* first received SLR TxFCf */
        uint32_t first_tx_FCb;           /* first received SLR TxFCb */
        uint32_t start_rx_FCl;           /* value of RxFCl at the beginning of the measurement perioed */
        uint32_t slm_test_id;

        uint32_t tx_FCl;                /* number of synthetic frame transmited towards the peer MEP */
        uint32_t rx_FCl;                /* number of synthetic frames received from the peer MEP */

        uint8_t override_mac;            /* If this flag is set, the user has specified a MAC address to use, rather than that of the interface chosen */
    };

    /* link list node for database */
    struct oam_entity_info
    {
        struct oam_entity info;
        struct oam_entity_info* next;
    };

/***************************/
/*       Global Variable   */
/***************************/
    extern struct oam_entity entity;
#ifdef	__cplusplus
}
#endif

#endif	/* PERFORMANCE_MANAGEMENT_ENTITY_H */

