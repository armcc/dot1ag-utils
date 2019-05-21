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

#ifndef ETH_SLR_H
#define	ETH_SLR_H
/***************************/
/*       HEADER            */
/***************************/
#include <net/ethernet.h>
#include <ieee8021ag.h>
#ifdef __cplusplus
extern "C" {
#endif

/***************************/
/*       MACRO             */
/***************************/
#define CFM_OPCODE_SLR 54        /* CFM OpCode for ETH-SLR - Relevant to MEPs */
#define CFM_TLVOFFSET_SLR 16     /* start of additional test TLVs or end TLV */

#define POS_CFM_SLR(s)      (struct y1731_eth_slr *) \
    (CFMHDR_U8((s), sizeof(struct cfmhdr)))

/***************************/
/*          ADT            */
/***************************/

    /****************************************************************/
    /*                      ETH-SLR                                 |
     *       1             2                 3             4        |
     *|-------------------------------------------------------------|
     *|       Source MEP ID          |       Responder MEP ID       |
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
    struct y1731_eth_slr {
        uint16_t      src_mepid;     /* 13 bit set to source MEP ID, bit 14~16
                                      * are set to 0; clause 9.22.1 */
        uint16_t      rsp_mepid;     /* 13 bit set to target MEP ID, bit 14~16
                                      * are set to 0; clause 9.22.1 */
        uint32_t      test_id;       /* unique test ID; clause 9.22.1 */
        uint32_t      txFCf;         /* number of SLM frames transmitted;
                                      * clause 9.22.1 */
        uint32_t      txFCb;         /* reserved to all 0 */
    } __attribute__ ((packed));

/***************************/
/*          Operations     */
/***************************/
    int32_t y1731_create_eth_slr(uint8_t *slm_buf,
                                 uint8_t *out_buf,
                                 uint32_t RxFCl);
    int32_t y1731_process_slr(char *ifname, uint8_t *slr_frame);

#ifdef __cplusplus
}
#endif

#endif /* Y1731_ETH_SLR_H */

