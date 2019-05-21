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

#ifndef ETH_SLM_H
#define	ETH_SLM_H

/***************************/
/*       HEADER            */
/***************************/
#include <net/ethernet.h>
#include "ieee8021ag.h"
#include "dot1ag_eth.h"

#ifdef __cplusplus
extern "C" {
#endif
#define CFM_OPCODE_SLM 55        /* CFM OpCode for ETH-SLM - Relevant to MEPs */
#define CFM_TLVOFFSET_SLM 16     /* start of additional test TLVs or end TLV */
/***************************/
/*          ADT            */
/***************************/

    /****************************************************************/
    /*                      ETH-SLM                                 |
     *       1             2                 3             4        |
     *|-------------------------------------------------------------|
     *|       Source MEP ID          | Reserved Responder MEP ID    |
     *|-------------------------------------------------------------|
     *|                         Test ID                             |
     *|-------------------------------------------------------------|
     *|                         TxFCf                               |
     *|-------------------------------------------------------------|
     *|                         TxFCb(0)                            |
     *|-------------------------------------------------------------|
     *|                    optional TLVs                            |
     *|-------------------------------------------------------------|
     * **************************************************************/
    struct y1731_eth_slm {
        uint16_t      src_mepid;     /* 13 bit set to source MEP ID, bit 14~16
                                      * are set to 0; clause 9.22.1 */
        uint16_t      res_rsp_mepid; /* 13 bit set to target MEP ID, bit 14~16
                                      * are set to 0; clause 9.22.1 */
        uint32_t      test_id;       /* unique test ID; clause 9.22.1 */
        uint32_t      txFCf;         /* number of SLM frames transmitted;
                                      * clause 9.22.1 */
        uint32_t      txFCb;         /* reserved to all 0 */
    } __attribute__ ((packed));

/***************************/
/*          Operations     */
/***************************/

    int32_t y1731_create_eth_slm(uint8_t *slm_buf, uint8_t* tgt_MAC);
    int32_t y1731_process_slm(char *ifname, uint8_t *slm_frame);


#ifdef __cplusplus
}
#endif

#endif /* ETH_SLM_H */

