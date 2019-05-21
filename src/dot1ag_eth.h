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

#ifndef DOT1AG_ETH_H
#define DOT1AG_ETH_H

/***************************/
/*       HEADER            */
/***************************/

#ifdef	__cplusplus
extern "C" {
#endif

/***************************/
/*        MACRO            */
/***************************/
#define SNAPLEN		65535	/* pcap snap length */
#define CFM_MODE          0
#define Y1731_MODE        1

#ifdef HAVE_NET_BPF_H

/*
 * FreeBSD has /dev/bpf als clone interface
 * MacOSX has /dev/bpf0, /dev/bpf1, ...
 */

#define NR_BPF_IFS	6
#define BPF_IFS_MAXLEN	10

#endif

/**************************************************************************/
/*! \fn get_local_mac(char *dev, uint8_t *ea)
**************************************************************************
*  \brief retrieve the MAC address of an interface.
*  \param[in] dev - device name
*  \param[out] ea  - MAC address
*  \return int 1 (success) or 0 (fail)
*/
int
get_local_mac(char *dev, uint8_t *ea);

/**************************************************************************/
/*! \fn send_packet( char *ifname, uint8_t *buf, int size)
**************************************************************************
*  \brief send the message via BPF interface
*  \param[in] ifname - outgoing interface
*  \param[in] buf    - packet buffer
*  \param[in] size   - size of the packet
*  \return int 1 (success) or 0 (fail)
*/
int
send_packet(char *ifname, uint8_t *buf, int size);

/**************************************************************************/
/*! \fn cfm_send_lbr(char *ifname, uint8_t *lbm_frame, int size)
**************************************************************************
*  \brief send the message via BPF interface
*  \param[in] ifname - outgoing interface
*  \param[in] buf    - packet buffer
*  \param[in] size   - size of the packet
*  \note everything regarding PBB-TE is not supported
*  \return int 1 (success) or 0 (fail)
*/
int
cfm_send_lbr(char *ifname, uint8_t *buf, int size);

/**************************************************************************/
/*! \fn process_ltm(char *ifname, uint8_t *ltm_frame)
**************************************************************************
*  \brief process ETH-LTM message and send out the ETH-LTR reply if
          there is no error in ETH-LTM
*  \param[in] ifname    - message receiving interface
*  \param[in] ltm_frame - packet/frame buffer with ethernet header
*  \return int 1 (success) or 0 (fail)
*/
int
process_ltm(char *ifname, uint8_t *ltm_frame);

/**************************************************************************/
/*! \fn process_ltr(char* ifname, uint8_t* ltr_frame
**************************************************************************
*  \brief process the ETH-Linktrace Reply message
*  \param[in] ifname - message receiver interface
*  \param[out] ltr_frame - LTR message buffer including Ethernet header
*  \Note  this function is not fully completed. We are not supporting server
*         functionalities. This function is used mainly for testing code.
*  \return int 1 (success) or 0 (fail)
*/
int
process_ltr(char* ifname, uint8_t* ltr_frame);

/**************************************************************************/
/*! \fn processLBR(char *ifname, uint8_t *lbr_frame)
**************************************************************************
*  \brief process the Loopback reply PDU.
*  \param[in] ifname - message receiving interface
*  \param[in] lbr_frame - message buffer including ethernet header
*  \return int 1 (proper ETH-LBR recevied) or 0 (fail)
*/
int
process_lbr(char *ifname, uint8_t *lbr_frame);

/**************************************************************************/
/*! \fn cfm_ccm_sender(char *ifname, uint16_t vlan, uint8_t md_level, char *md,
                char *ma, uint16_t mepid, int interval)
**************************************************************************
*  \brief periodically send out CCM message
*  \param[in] ifname   - message traffic interface
*  \param[in] vlan     - vlan encapsulation value
*  \param[in] md_level - current entity MEG level
*  \param[in] md       - Maintenance Domain Name
*  \param[in] ma       - Maintenance Association Name
*  \param[in] interval - heart beat rate of ccm message
*  \Note  this function is not fully completed. We are not supporting server
*         functionalities.
*  \return int 1 (success) or 0 (fail)
*/
int
cfm_ccm_sender(char *ifname, uint16_t vlan, uint8_t md_level, char *md,
            char *ma, uint16_t mepid, int interval);

/**************************************************************************/
/*! \fn print_ltr(uint8_t *buf)
**************************************************************************
*  \brief print out the ETH-LTR
*  \param[in] buf - ETH-LTR frame buffer
*  \return void
*/
void
print_ltr(uint8_t *buf);

/**************************************************************************/
/*! \fn create_eth_lbm(uint8_t *lbm_buf,
 *                     const uint8_t meg_level,
 *                     const uint32_t test_seq,
 *                     uint8_t *pbb_te_mip_tlv,
 *                     uint8_t *data_tlv,
 *                     uint8_t *test_tlv,
 *                     uint8_t *tgt_MAC)
**************************************************************************
*  \brief create an targt entity in database and create an ETH-LBM pdu.
*  \param[in] meg_level - entity meg level
*  \param[in] test_seq - testing sequence for LBM message
*  \param[in] pbb_te_mip_tlv -PBB-TE TLV (18 octets)
*  \param[in] data_tlv - data tlv (maximum length is 1480)
*  \param[in] test_tlv - test pattern TLV (maximum length is 1480)
*  \param[in] tgt_MAC  - targeting MEP MAC address
*  \param[out] lbm_buf - buffer address after Ethernet header
*  \return int 1 (success) or 0 (fail)
*/
int
create_eth_lbm(uint8_t *lbm_buf,
               const uint8_t meg_level,
               const uint32_t test_seq,
               uint8_t *pbb_te_mip_tlv,
               uint8_t *dataTLV,
               uint8_t *testTLV,
               uint8_t *tgt_MAC);

/**************************************************************************/
/*! \fn create_eth_ltm(uint8_t *ltm_buf,
 *                     const uint8_t meg_level,
 *                     const uint8_t flag,
 *                     struct cfm_ltm *ltm_pdu,
 *                     uint8_t *egress_mac))
**************************************************************************
*  \brief create an targt entity in database and create a ETH-LTM pdu.
*  \param[in] meg_level - entity meg level
*  \param[in] flag - flags for LTM PDU
*  \param[in] ltm_pdu - input value for LTM message
*  \param[in] egress_mac - egress Identifier TLV
*  \param[out] ltm_buf - buffer address after Ethernet header
*  \return int 1 (success) or 0 (fail)
*/
int
create_eth_ltm(uint8_t *ltm_buf,
               const uint8_t meg_level,
               const uint8_t flag,
               struct cfm_ltm *ltm_pdu,
               uint8_t* egress_mac);

/**************************************************************************/
/*! \fn open_listen_socket(int* sockFD, char *ifname)
**************************************************************************
*  \brief create an socket for PF_INET and raw socket type.
*  \param[in] ifname - interface name which bind to the socket
*  \param[out] sockFD -  raw socket
*  \return int 1 (success) or 0 (fail)
*/
int
open_listen_socket_raw(int* sockFD, char *ifname);

/**************************************************************************/
/*! \fn receive_msg(int socketFD, uint8_t* buf, size_t buf_size, int* msg_size)
**************************************************************************
*  \brief calling recvmsg to receive raw packet and filter with 0x8100 or 0x8902
*  \param[in] buf_size - size of the buffer passed in as argument 2
*  \param[out] sockFD  - raw socket to receive message
*  \param[out] buf     - buffer of received packet
*  \param[out] msg_sze - received packet size
*  \return int 1 (success) or 0 (fail)
*/
int
receive_msg(int *socketFD, uint8_t* buf, size_t buf_size, int* msg_size);

#ifdef __cplusplus
}
#endif

#endif
