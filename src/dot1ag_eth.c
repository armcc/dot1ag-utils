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

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <time.h>

#include <sys/ioctl.h>

#ifdef HAVE_NET_BPF_H
#include <sys/types.h>
#include <net/bpf.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#else
#include <netpacket/packet.h>
#endif

#include "ieee8021ag.h"
#include "dot1ag_eth.h"
#include "eth_slm.h"
#include "eth_slr.h"
#include "oam_db.h"
#include "oam_entity.h"

/*FUTURE_DEVELOPMENT: replace bug report from printf to a debug tool, which can be turned on and off via CLI */
#define ETH_P_CFM   0x8902

/***************************/
/*    global variable      */
/***************************/
extern struct oam_entity entity;

/*********************************/
/*   local function declaration  */
/*********************************/
static int
oam_create_eth_lbm(uint8_t *lbm_buf,
const uint8_t meg_level,
const uint32_t test_seq,
uint8_t *pbb_te_mip_tlv,
uint8_t *data_tlv,
uint8_t *test_tlv);

static int
oam_create_eth_ltm(uint8_t *ltm_buf,
const uint8_t meg_level,
const uint8_t flag,
struct cfm_ltm *ltm_pdu,
    uint8_t* egress_mac);

/*********************************/
/*   function definition         */
/*********************************/
#ifdef HAVE_NET_BPF_H

char bpf_ifs[NR_BPF_IFS][BPF_IFS_MAXLEN] = {
    "/dev/bpf",
    "/dev/bpf0",
    "/dev/bpf1",
    "/dev/bpf2",
    "/dev/bpf3",
    "/dev/bpf4" };

/**************************************************************************/
/*! \fn get_local_mac(char *dev, uint8_t *ea)
**************************************************************************
*  \brief retrieve the MAC address of an interface.
*  \param[in] dev - device name
*  \param[out] ea  - MAC address
*  \return int 1 (success) or 0 (fail)
*/
int
get_local_mac(char *dev, uint8_t *ea) {
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_dl *sdl;
    caddr_t addr;
    int i;

    if (entity.override_mac) {
        memcpy(ea, entity.mac, sizeof(entity.mac));
        return 1;
    }

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 0;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        if (strncmp(ifa->ifa_name, dev, sizeof(dev)) != 0) {
            continue;  /* not the interface we are looking for */
        }
        sdl = (struct sockaddr_dl *) ifa->ifa_addr;
        if (sdl->sdl_family != AF_LINK) {
            continue;  /* skip if this not a data link address */
        }
        addr = LLADDR(sdl);
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            ea[i] = addr[i];
        }
        return 1;
    }
    freeifaddrs(ifaddr);
    /* interface not found, return 0 */
    return 0;
}

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
send_packet(char *ifname, uint8_t *buf, int size) {
    int bpf;
    struct ifreq ifc;
    int complete_header = 1;
    int i;

    if (geteuid() != 0) {
        fprintf(stderr, "%s :: Execution requires superr privilege.\n", __func__);
        return 0;
    }

    /* minimum size of Ethernet frames is ETHER_MIN_LEN octets */
    if (size < ETHER_MIN_LEN) {
        size = ETHER_MIN_LEN;
    }

    /* try to open BPF interfaces until it success */
    for (i = 0; i < NR_BPF_IFS; i++) {
        if ((bpf = open(bpf_ifs[i], O_RDWR)) == -1) {
            continue;
        }
        else {
            break;
        }
    }
    if (bpf == -1) {
        /* failed to open a BPF interface */
        return 0;
    }

    /* bind BPF to the outgoing interface */
    strncpy(ifc.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(bpf, BIOCSETIF, &ifc) > 0) {
        perror("BIOCSETIF");
        return 0;
    }
    /* tell BPF that frames contain an Ethernet header */
    if (ioctl(bpf, BIOCSHDRCMPLT, &complete_header) < 0) {
        perror("BIOCSHDRCMPLT");
        return 0;
    }
    if (write(bpf, buf, size) < 0) {
        perror("/dev/bpf");
        return 0;
    }
    close(bpf);
    return 0;
}

#else
/**************************************************************************/
/*! \fn get_local_mac(char *dev, uint8_t *ea)
**************************************************************************
*  \brief retrieve the MAC address of an interface.
*  \param[in] dev - device name
*  \param[out] ea  - MAC address
*  \return int 1 (success) or 0 (fail)
*/
int
get_local_mac(char *dev, uint8_t *ea) {
    int s;
    int i;
    struct ifreq req;

    if (entity.override_mac) {
        memcpy(ea, entity.mac, sizeof(entity.mac));
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "%s :: Execution requires superuser privilege.\n", __func__);
        return 0;
    }

    if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("opening socket");
        return 0;
    }

    /* get interface index */
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, dev, sizeof(req.ifr_name) - 1);

    /* get MAC address of interface */
    if (ioctl(s, SIOCGIFHWADDR, &req)) {
        perror(dev);
        return 0;
    }
    close(s);
    for (i = 0; i < ETH_ALEN; i++) {
        ea[i] = req.ifr_hwaddr.sa_data[i];
    }
    return 1;
}

/**************************************************************************/
/*! \fn send_packet( char *ifname, uint8_t *buf, int size)
**************************************************************************
*  \brief send the message via raw ethernet socket
*  \param[in] ifname - outgoing interface
*  \param[in] buf    - packet buffer
*  \param[in] size   - size of the packet
*  \return int 1 (success) or 0 (fail)
*/
int
send_packet(char *ifname, uint8_t *buf, int size) {
    int ifindex = 0,
        sockFD = 0,
        flag = MSG_DONTWAIT;
    struct ifreq req;
    struct sockaddr_ll addr_out;
    struct iovec iov[1];
    struct msghdr msghdr;
#ifdef L2VPN_SUPPORT
    int optval = 1;
    union {
        char control[CMSG_SPACE(sizeof(struct ti_auxdata))];
        struct cmsghdr align;
    } ti_aux_u;
    struct ti_auxdata tx_ti_aux;
    struct ti_auxdata * ti_aux_ptr;
    struct cmsghdr *cmsg;
#endif

    if (geteuid() != 0) {
        fprintf(stderr, "%s :: Execution requires superuser privilege.\n", __func__);
        return 0;
    }

    /* minimum size of Ethernet frames is ETHER_MIN_LEN octets */
    if (size < ETHER_MIN_LEN) {
        size = ETHER_MIN_LEN;
    }

    /* open raw Ethernet socket for sending */
    if ((sockFD = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("opening socket");
        return 0;
    }

#ifdef L2VPN_SUPPORT
    if (entity.sf_index_valid) {
        setsockopt(sockFD, SOL_PACKET, TI_AUXDATA, &optval, sizeof optval);
    }
#endif

    /* get interface index */
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name) - 1);
    if (ioctl(sockFD, SIOCGIFINDEX, &req)) {
        perror(ifname);
        return 0;
    }
    ifindex = req.ifr_ifindex;

    /* set socket address parameters */
    memset(&addr_out, 0, sizeof(addr_out));
    addr_out.sll_family = AF_PACKET;
    addr_out.sll_protocol = htons(ETH_P_ALL);
    addr_out.sll_halen = ETH_ALEN;
    addr_out.sll_ifindex = ifindex;
    addr_out.sll_pkttype = PACKET_OTHERHOST;

    memset(iov, 0, sizeof(iov));
    memset(&msghdr, 0, sizeof(msghdr));
    iov[0].iov_base = (char*)buf;
    iov[0].iov_len = size;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_name = &addr_out,
        msghdr.msg_namelen = sizeof(addr_out);

#ifdef L2VPN_SUPPORT
    /* If upstream service flow index was supplied on commandline, send it in upstream metadata */
    if (entity.sf_index_valid) {
        tx_ti_aux.ti_meta_info = ((entity.sf_index << L2VPN_SF_INDEX_OFFSET) & L2VPN_SF_INDEX_MASK);
        tx_ti_aux.ti_meta_info2 = 0;
        //Fill out an send ti auxilliary message
        msghdr.msg_control = ti_aux_u.control;
        msghdr.msg_controllen = sizeof(ti_aux_u.control);
        cmsg = CMSG_FIRSTHDR(&msghdr);
        cmsg->cmsg_level = SOL_PACKET;
        cmsg->cmsg_type = TI_AUXDATA;
        cmsg->cmsg_len = CMSG_LEN(sizeof(tx_ti_aux));
        ti_aux_ptr = (struct ti_auxdata *) CMSG_DATA(cmsg);
        memcpy(ti_aux_ptr, &tx_ti_aux, sizeof(tx_ti_aux));
    }
#endif

    if (0 > sendmsg(sockFD, &msghdr, flag)) {
        perror("sendmsg");
    }
    close(sockFD);
    return 0;
}

#endif

/**************************************************************************/
/*! \fn print_ltr(uint8_t *buf)
**************************************************************************
*  \brief print out the ETH-LTR
*  \param[in] buf - ETH-LTR frame buffer
*  \return void
*/
void
print_ltr(uint8_t *buf) {
    struct cfmencap *encap;
    struct cfm_ltr *ltr;

    printf("\treply from ");
    encap = (struct cfmencap *) buf;
    eaprint(encap->srcmac);

    ltr = POS_CFM_LTR(buf);
    printf(", id=%d, ttl=%d", htonl(ltr->transID), ltr->ttl);
    switch (ltr->action) {
    case ACTION_RLYHIT:
        printf(", RlyHit\n");
        break;
    case ACTION_RLYFDB:
        printf(", RlyFDB\n");
        break;
    case ACTION_RLYMPDB:
        printf(", RlyMPDB\n");
        break;
    default:
        printf(", RlyUknown\n");
    }
}

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
cfm_send_lbr(char *ifname, uint8_t *lbm_frame, int size) {
    uint8_t lbr_frame[ETHER_MAX_LEN];
    uint8_t local_mac[ETHER_ADDR_LEN];
    struct cfmhdr *lbr_cfmhdr = NULL;
    struct cfmhdr *lbm_cfmhdr = NULL;
    struct ether_header *lbm_ehdr = NULL;
    struct ether_header *lbr_ehdr = NULL;
    int i = 0;
    uint8_t md_level = 0;

    if ((NULL == ifname) || (NULL == lbm_frame))
    {
        return 0;
    }
    if ((ETHER_MIN_LEN > size) || (ETHER_MAX_LEN < size))
    {
        return 0;
    }
    if (get_local_mac(ifname, local_mac) != 1) {
        fprintf(stderr, "%s :: Cannot determine local MAC address\n", __func__);
        return 0;
    }

    lbm_ehdr = (struct ether_header *) lbm_frame;
    lbr_ehdr = (struct ether_header *) lbr_frame;

    /* silently discard frame if it was sent by us */
    if (ETHER_IS_EQUAL(lbm_ehdr->ether_shost, local_mac)) {
        return 0;
    }
    /* check for valid source mac address */
    /* note: according to clause y1731-7.2.2, the destination MAC in the LBR
    frame is copied from the source MAC of the multicast LBM frame
    which should be a unicast address. */
    if (ETHER_IS_MCAST(lbm_ehdr->ether_shost)) {
        fprintf(stderr, "%s :: LBR received from multicast address\n", __func__);
        return 0;
    }

    /*
    * Destination mac address should be either our MAC address or the
    * CCM group address.
    */
    /* 802.1Q clause 20.2.2 */
    if (!(ETHER_IS_CCM_GROUP(lbm_ehdr->ether_dhost) ||
        ETHER_IS_EQUAL(lbm_ehdr->ether_dhost, local_mac))) {
        /* silently drop LBM */
        return 0;
    }

    /* clause 7.2.2.2 validity of the multicast LBM frame is determined based
    on the correct MEG level */
    lbm_cfmhdr = CFMHDR(lbm_frame);
    md_level = GET_MD_LEVEL(lbm_cfmhdr);
    if (entity.meg_level != md_level) {
        fprintf(stderr, "%s :: MEG level does not match\n", __func__);
        return 0;
    }

    if (CFM_OPCODE_LBM != lbm_cfmhdr->opcode) {
        fprintf(stderr, "%s :: PDU is not ETH_LBM\n", __func__);
        return 0;
    }

    /* clear outgoing packet buffer 'lbr_frame' */
    memset(lbr_frame, 0, sizeof(lbr_frame));

    /* copy received LBM to 'lbr_frame' */
    memcpy(lbr_frame, lbm_frame, size);

    /* set proper src and dst mac addresses */
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        lbr_ehdr->ether_shost[i] = local_mac[i];
        lbr_ehdr->ether_dhost[i] = lbm_ehdr->ether_shost[i];
    }

    lbr_cfmhdr = CFMHDR(lbr_frame);
    lbr_cfmhdr->opcode = CFM_OPCODE_LBR;

    if (send_packet(ifname, lbr_frame, size) < 0) {
        perror("send_packet");
        return 0;
    }

    return 1;
}


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
process_ltm(char *ifname, uint8_t *ltm_frame) {
    int i;
    uint8_t outbuf[ETHER_MAX_LEN];
    int size = 0;
    struct cfmencap *encap;
    struct ether_header *ltm_ehdr;
    uint8_t local_mac[ETHER_ADDR_LEN];
    uint8_t flags;
    uint8_t action;
    uint16_t vlan;
    uint8_t ttl;
    int pktsize = 0;
    struct cfmhdr *cfmhdr;
    uint8_t md_level = 0;
    uint32_t transid;
    struct cfm_ltm *cfm_ltm = NULL;
    uint8_t* tlv_ptr = NULL;
    uint8_t egress_id_tlv_found = 0;

    if ((NULL == ifname) || (NULL == ltm_frame)) {
        fprintf(stderr, "%s :: invalid input argument\n", __func__);
        return 0;
    }

    if (get_local_mac(ifname, local_mac) != 1) {
        fprintf(stderr, "%s :: Cannot determine local MAC address\n", __func__);
        return 0;
    }

    ltm_ehdr = (struct ether_header *) ltm_frame;
    /* silently discard frame if it was sent by us */
    if (ETHER_IS_EQUAL(ltm_ehdr->ether_shost, local_mac)) {
        return 0;
    }

    encap = (struct cfmencap *) ltm_frame;
    if (IS_TAGGED(ltm_frame)) {
        vlan = ntohs(encap->tci) & 0x0fff;
    }
    else {
        vlan = 0;
    }
    cfmhdr = CFMHDR(ltm_frame);
    md_level = GET_MD_LEVEL(cfmhdr);
    /* Y.1731 clause 7.3.2 */
    if (entity.meg_level != md_level) {
        /* MEP at a higher MD level discards the LTM and MP at an
        equal MD level directs the LTM to its Bridge's Linktrace
        responder. */
        fprintf(stderr, "%s :: MEG level does not match\n", __func__);
        return 0; /*not valid LTM frame */
    }

    if (CFM_OPCODE_LTM != cfmhdr->opcode) {
        fprintf(stderr, "%s :: PDU is not ETH_LTM\n", __func__);
        return 0;
    }

    /* copy fields from LTM PDU */
    flags = cfmhdr->flags;
    /*FUTURE_DEVELOPMENT : check the following if supporting MIP:
    1. UseFDBonly bit set to 0
    2. Target MAC address is found in the bridge's MIP CCM Database
    3. entry in the MIP CCM Database identifies a Bridge Port */

    /* clear FwdYes bit to indicate that we did not forward */
    flags &= ~DOT1AG_LTFLAGS_FWDYES;
    /* set TerminalMEP bit */
    /* The current design is only supporting MEP */
    if (MEP == entity.mep_mip) {
        flags |= DOT1AG_LTFLAGS_TERMINALMEP;
    }

    cfm_ltm = POS_CFM_LTM(ltm_frame);
    transid = ntohl(cfm_ltm->transID);
    ttl = cfm_ltm->ttl;
    /* do not send LTR when TTL = 0 */
    if (ttl == 0) {
        return 0;
    }
    ttl--;

    /* loop through the TLVs for the existance of TLV_LTM_EGRESS_IDENTIFIER */
    tlv_ptr = ((uint8_t*)cfm_ltm) + sizeof(struct cfm_ltm);
    /* the last TLV encapsulated in all CFMs should be TLV_END, 0 */

    while ((TLV_END != *tlv_ptr) && (1 != egress_id_tlv_found)) {
        switch (*tlv_ptr)
        {
            case TLV_LTM_EGRESS_IDENTIFIER:
                egress_id_tlv_found = 1;
                break;
            default:
            {
                tlv_ptr += 1; /* increase 1 octet to the tlv length field */
                uint16_t* tlv_length_ptr = (uint16_t*)tlv_ptr;
                uint16_t tlv_length = ntohs(*tlv_length_ptr);
                tlv_ptr += 2; /* increase 2 octets to the data field */
                tlv_ptr += tlv_length; /* set the tlv_ptr to the head of next tlv protocol */
            }
                break;
        }
    }
    if ( (0 == egress_id_tlv_found) && (CFM_MODE == entity.operation_mode)) {
        return  0;
    }

    /* MEP or MIP responds with LTR only if
    * 1: MEP or MIP is aware of the TargetMAC address in the LTM and associates it to a
    *    single egress port, where the egress port is not the same as the port on which the frame
    *    with LTM information is received or
    * 2: TargetMAC address is the same as the MIP's or MEP;s own MAC address.
    */
    /*NOTE: make sure statement 1 is satisfied */

    /*
    * Destination mac address should be either our MAC address or the
    * LTM group address.
    */

    if (!(ETHER_IS_LTM_GROUP(ltm_ehdr->ether_dhost) ||
        ETHER_IS_EQUAL(ltm_ehdr->ether_dhost, local_mac) ||
        ETHER_IS_EQUAL(cfm_ltm->target_mac, local_mac))) {
        /* silently drop LTM */
        return 0;
    }

    /*
    * Below the outgoing LTR Ethernet frame is built
    */

    /* clear outgoing packet buffer 'outbuf' */
    memset(outbuf, 0, sizeof(outbuf));

    /* add CFM encapsulation header to packet */
    cfm_add_encap(vlan, local_mac, cfm_ltm->orig_mac, outbuf, &size);
    pktsize += size;

    /* add CFM common header to packet */
    /* FwdYes bit has been set to 0*/
    cfm_add_hdr(md_level, flags, FIRST_TLV_LTR, CFM_OPCODE_LTR, outbuf + pktsize);
    pktsize += sizeof(struct cfmhdr);

    /* RlyMPDB is defined as The Egress Port was determined by consulting the MIP
    CCM Database. We are not supporting MIP */
    if (ETHER_IS_EQUAL(cfm_ltm->target_mac, local_mac)) {
        action = ACTION_RLYHIT;
    }
    else {
        action = ACTION_RLYFDB;
    }
    cfm_add_ltr(transid, ttl, action, outbuf + pktsize);
    pktsize += sizeof(struct cfm_ltr);

    /*
    *  finally add LTR Egress Identifier TLV
    */

    /* XXX code below needs cleanup */
    /* Type */
    *(uint8_t *)(outbuf + pktsize) = TLV_LTR_EGRESS_IDENTIFIER;
    pktsize += sizeof(uint8_t);

    /* LTR Egress Identifier is 16 octets */
    *(uint16_t *)(outbuf + pktsize) = htons(TLV_LTR_EGRESS_ID_LENGTH);
    pktsize += sizeof(uint16_t);

    /* add Last Egress Identifier TLV */
    /* Unique Identifier (set to 0) */
    tlv_ptr += 5; /* tlv header ; 1 octet type, 2 octets length; 2 octets zeros */

    *(uint16_t *)(outbuf + pktsize) = htons(0);
    pktsize += sizeof(uint16_t);
    /* MAC address of sender/forwarder of LTM */
    if (1 == egress_id_tlv_found) {
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            *(outbuf + pktsize + i) = *(tlv_ptr + i);
        }
    }
    else {
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            *(outbuf + pktsize + i) = ltm_ehdr->ether_shost[i];
        }
    }

    pktsize += ETHER_ADDR_LEN;

    /* add Next Egress Identifier TLV; this section is undefined only if FwdYes bit of
    *  Flags field is 0; this is our current setup
    */
    /* LTM is not relayed only when a MIP receives LTM with TTL = 1*/
    /* Unique Identifier (set to 0) */
    /*NOTE: if LTM_Egress_Identifier TLV present, we should use the LTM_Egress_ID_TLV
    or the link responder that transmitted this LTR for this section*/
    *(uint16_t *)(outbuf + pktsize) = htons(0);
    pktsize += sizeof(uint16_t);
    /* our MAC address */
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        *(outbuf + pktsize + i) = local_mac[i];
    }
    pktsize += ETHER_ADDR_LEN;

    /* add Reply Ingress TLV when LTM frame was received by a MIP or MEP at an ingress port.
    * otherwise, add a reply egress TLV if the egress port has a MIP or MEP (most likely happened
    * when the receiver is a MIP
    */
    /*FUTURE_DEVELOPMENT: add Reply Egress TLV if required */
    /* type */
    *(uint8_t *)(outbuf + pktsize) = TLV_REPLY_INGRESS;
    pktsize += sizeof(uint8_t);

    /* length */
    *(uint16_t *)(outbuf + pktsize) = htons(TLV_REPLY_INGRESS_LENGTH);
    pktsize += sizeof(uint16_t);

    /* action */
    *(uint8_t *)(outbuf + pktsize) = DOT1AG_IngOK;
    pktsize += sizeof(uint8_t);

    /* our MAC address */
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        *(outbuf + pktsize + i) = local_mac[i];
    }
    pktsize += ETHER_ADDR_LEN;

    /* end packet with End TLV field */
    *(uint8_t *)(outbuf + pktsize) = TLV_END;
    pktsize += sizeof(uint8_t);

    /* Assembled Ethernet frame is 'outbuf', its size is 'pktsize' */

    if (send_packet(ifname, outbuf, pktsize) < 0) {
        perror("send_packet");
        return(0);
    }

    return 1;
}

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
int process_ltr(char* ifname, uint8_t* ltr_frame) {

    struct ether_header *ltr_ehdr;
    uint8_t local_mac[ETHER_ADDR_LEN];
    struct cfmhdr *cfmhdr = NULL;
    struct cfm_ltr *cfm_ltr = NULL;
    struct timeval recv_time;
    struct oam_entity_info* entity_db = NULL;

    if ((NULL == ifname) ||
        (NULL == ltr_frame)) {
        fprintf(stderr, "%s :: invalid input argument\n", __func__);
        return 0;
    }

    gettimeofday(&recv_time, NULL);
    if (get_local_mac(ifname, local_mac) != 1) {
        fprintf(stderr, "%s :: Cannot determine local MAC address\n", __func__);
        return 0;
    }
    ltr_ehdr = (struct ether_header *) ltr_frame;

    /* silently discard frame if it was sent by us */
    if (ETHER_IS_EQUAL(ltr_ehdr->ether_shost, local_mac)) {
        return 0;
    }

    cfmhdr = CFMHDR(ltr_frame);

    if (CFM_OPCODE_LTR != cfmhdr->opcode) {
        fprintf(stderr, "%s :: PDU is not ETH_LTR\n", __func__);
        return 0;
    }

    if (FIRST_TLV_LTR > cfmhdr->tlv_offset) {
        fprintf(stderr, "%s :: First TLV Offset is smaller than 6\n", __func__);
        return 0;
    }

    cfm_ltr = POS_CFM_LTR(ltr_frame);

    if ((ACTION_RLYMPDB != cfm_ltr->action) &&
        (ACTION_RLYFDB != cfm_ltr->action) &&
        (ACTION_RLYHIT != cfm_ltr->action)) {
        fprintf(stderr, "%s :: Relay Action undefined\n", __func__);
        return 0;
    }

    if (ETHER_IS_EQUAL(ltr_ehdr->ether_dhost, local_mac)) {
        /* if a MIP receives an LTR frame addressed to it, MIP should
        discard it. If destination addrss parameter does not match the MAC
        address of the Bridge Port on which the MEP resides.  */
        return 0;
    }

    /* NOT SUPPORTING this feature */
    /* FUTURE_DEVELOPMENT: Reply Ingress TLV validation :
    *  1. validate if Ingress Action field is defined enumerated in 802.1Q 21.9.8.1
    *  2. Ingress MAC address field contains an Individual, not a Greoup MAC address
    *  3. LEngth field either is 7 (no Ingress Port ID) or is 9 + Ingress Port ID length
    *   or larger
    */
    if (NULL != (entity_db = oam_find_entity_by_mac(ltr_ehdr->ether_shost))) {
        uint32_t deltaTimeSec = (uint32_t)(recv_time.tv_sec - entity_db->info.ltm_tx_time.tv_sec);
        if (LTR_TIMEOUT < deltaTimeSec) {
            fprintf(stderr, "LTR received later than 5 seconds; LTR discard\n");
            return 0;
        }
        else {
            if (0 != (cfmhdr->flags & DOT1AG_LTFLAGS_FWDYES)) {
                /*FUTURE_DEVELOPMENT: process Next Egress Identifier if only if modified LTM frame is relayed,
                the FwdYes bit of the Flags field in LTM is not 0*/
                /* FUTURE_DEVELOPMENT: (Linktrace database is needed )need to create a list of transmitted transaction
                numbers; remove the latest number whenever one is received or pass 5 seconds;
                in addition, this number cannot be reused in 1 minutes.
                Will support this in the future, since we are not expecting to support LTR for now */
                /*FUTURE_DEVELOPMENT: linktrace database store the LTR with index value of 1 if no entry exists in
                the Database for this MEP, corresponding to the LTR transaction Identifier field. If
                an entry exist, it create a new entry with an index value one greater than the
                last matching LTR */

            }
        }
    }
    return 1;
}
/* CCM sequence number */
static uint32_t CCIsentCCMs = 0;
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
int cfm_ccm_sender(char *ifname, uint16_t vlan, uint8_t md_level, char *md,
    char *ma, uint16_t mepid, int interval) {
    uint8_t outbuf[ETHER_MAX_LEN];
    uint8_t local_mac[ETHER_ADDR_LEN];
    uint8_t remote_mac[ETHER_ADDR_LEN];
    uint8_t flags;
    int pktsize = 0;
    int size = 0;
    int CCMinterval = 4;    /* default to 1 sec */
    struct cfm_cc *cfm_cc;
    uint8_t *p;
    int mdnl;
    int smanl;
    int max_smanl;

    if (get_local_mac(ifname, local_mac) != 1) {
        fprintf(stderr, "%s :: Cannot determine local MAC address\n", __func__);
        return 0;
    }

    /*
    * Below the outgoing Ethernet frame is built
    */

    /* clear outgoing packet buffer */
    memset(outbuf, 0, sizeof(outbuf));

    /* add CFM encapsulation header to packet */
    eth_addr_parse(remote_mac, ETHER_CFM_GROUP);
    remote_mac[5] = 0x30 + (md_level & 0x0F);
    cfm_add_encap(vlan, local_mac, remote_mac, outbuf, &size);
    pktsize += size;

    /* RDI in flag field is always set to 0 */
    flags = 0;
    /* least-significant three bits are the CCM Interval */
    switch (interval) {
    case 10:
        /* 10 ms */
        CCMinterval = 2;
        break;
    case 100:
        /* 100 ms */
        CCMinterval = 3;
        break;
    case 1000:
        /* 1 sec */
        CCMinterval = 4;
        break;
    case 10000:
        /* 10 sec */
        CCMinterval = 5;
        break;
    case 60000:
        /* 1 min */
        CCMinterval = 6;
        break;
    case 600000:
        /* 10 min */
        CCMinterval = 7;
        break;
    default:
        /* 1 sec */
        CCMinterval = 4;
        break;
    }
    flags |= (CCMinterval & 0x07);

    /* add CFM common header to packet */
    cfm_add_hdr(md_level, flags, FIRST_TLV_CCM, CFM_OPCODE_CCM,
        outbuf + pktsize);
    pktsize += sizeof(struct cfmhdr);

    cfm_cc = (struct cfm_cc *) (outbuf + pktsize);
    /* add 4 octet Sequence Number to packet */
    cfm_cc->seqNumber = htonl(CCIsentCCMs);
    CCIsentCCMs++;
    cfm_cc->mepid = htons(mepid);
    /* XXX always assume character string format */
    /* use character string (4) as Maintenance Domain Name Format */
    cfm_cc->maid.format = 4;
    cfm_cc->maid.length = strlen(md);
    if (cfm_cc->maid.length > DOT1AG_MAX_MD_LENGTH) {
        cfm_cc->maid.length = DOT1AG_MAX_MD_LENGTH;
    }
    /* set p to start of variable part in MAID */
    p = cfm_cc->maid.var_p;
    /* fill variable part of MAID with 0 */
    memset(p, 0, sizeof(cfm_cc->maid.var_p));
    /* copy Maintenance Domain Name to MAID */
    mdnl = strlen(md);
    if (mdnl > DOT1AG_MAX_MD_LENGTH) {
        mdnl = DOT1AG_MAX_MD_LENGTH;
    }
    memcpy(p, md, mdnl);
    p += mdnl;
    /* XXX always assume character string format */
    /* set Short MA Name Format to character string (2) */
    *p = 2;
    p++;
    /* set Short MA Name Length */
    max_smanl = sizeof(struct cfm_maid) - 4 - mdnl;
    smanl = strlen(ma);
    if (smanl > max_smanl) {
        smanl = max_smanl;
    }
    *p = smanl;
    p++;
    /* copy Short MA Name to MAID */
    memcpy(p, ma, smanl);
    /* field defined by ITU-T Y.1731, transmit as 0 */
    memset(cfm_cc->y1731, 0, sizeof(cfm_cc->y1731));

    pktsize += sizeof(struct cfm_cc);

    /* add Sender ID TLV */
    /* Type */
    *(uint8_t *)(outbuf + pktsize) = TLV_SENDER_ID;
    pktsize += sizeof(uint8_t);
    /* minimal length of 1 */
    *(uint16_t *)(outbuf + pktsize) = htons(1);
    pktsize += sizeof(uint16_t);
    /* Chassis ID Length is 0 (no Chassis ID present) */
    *(uint8_t *)(outbuf + pktsize) = 0;
    pktsize += sizeof(uint8_t);

    /* add Port Status TLV */
    /* Type */
    *(uint8_t *)(outbuf + pktsize) = TLV_PORT_STATUS;
    pktsize += sizeof(uint8_t);
    /* minimal length of 1 */
    *(uint16_t *)(outbuf + pktsize) = htons(1);
    pktsize += sizeof(uint16_t);
    /* Port Status, XXX hard code to psUp */
    *(uint8_t *)(outbuf + pktsize) = DOT1AG_PS_UP;
    pktsize += sizeof(uint8_t);

    /* add Interface Status TLV */
    /* Type */
    *(uint8_t *)(outbuf + pktsize) = TLV_INTERFACE_STATUS;
    pktsize += sizeof(uint8_t);
    /* minimal length of 1 */
    *(uint16_t *)(outbuf + pktsize) = htons(1);
    pktsize += sizeof(uint16_t);
    /* Interface Status, XXX hard code to isUp */
    *(uint8_t *)(outbuf + pktsize) = DOT1AG_IS_UP;
    pktsize += sizeof(uint8_t);

    /* end packet with End TLV field */
    *(uint8_t *)(outbuf + pktsize) = htons(TLV_END);
    pktsize += sizeof(uint8_t);

    /* Assembled Ethernet frame is 'outbuf', its size is 'pktsize' */
    if (send_packet(ifname, outbuf, pktsize) < 0) {
        fprintf(stderr, "%s :: send_packet failed\n", __func__);
        return 0;
    }
    return 1;
}

/**************************************************************************/
/*! \fn oam_create_eth_lbm(uint8_t *lbm_buf,
*                         const uint8_t meg_level,
*                         const uint32_t test_seq,
*                         uint8_t *pbb_te_mip_tlv,
*                         uint8_t *data_tlv,
*                         uint8_t *test_tlv,
*                         uint8_t *tgt_MAC)
**************************************************************************
*  \brief create an ETH-LBM pdu. If Data and Test TLVs are presenting,
*         the overall size must not exceed a ethernet packet (1492).
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
oam_create_eth_lbm(uint8_t *lbm_buf,
const uint8_t meg_level,
const uint32_t test_seq,
uint8_t *pbb_te_mip_tlv,
uint8_t *dataTLV,
uint8_t *testTLV) {
    /* MAKE sure the test_seq is unique within every lbm send over;
    if using seq number, it should be increased by 1 whenever a LBM transmitted. */
    int32_t length = 0;

    if (NULL == lbm_buf) {
        return length;
    }
    /* fill in the common header section */
    cfm_add_hdr(meg_level, 0, FIRST_TLV_LBM, CFM_OPCODE_LBM, lbm_buf);
    length += sizeof(struct cfmhdr);

    struct cfm_lbm *lbm = (struct cfm_lbm*) (lbm_buf + length);
    lbm->trans_id = htonl(test_seq);
    length += sizeof(struct cfm_lbm);
#if 0 /* FUTURE_DEVELOPMENT: this section is not valid since we are not supporting PBB-TE MIP */
    if (NULL != pbb_te_mip_tlv) {
        /* ignore the TLV if data type is not 9 */
        uint8_t* ptr = pbb_te_mip_tlv;
        uint8_t type = *ptr;
        ptr += 1; /* type is 1 octect long */
        uint16_t pbb_te_mip_tlv_length = htons(*((uint16_t*)ptr));
        ptr += 2; /* length is 2 octect long */
        uint8_t mip_mac_addr[ETHER_ADDR_LEN];
        memcpy(mip_mac_addr, ptr, ETHER_ADDR_LEN);
        ptr += ETHER_ADDR_LEN;
        uint16_t reverse_vid = *((uint16_t*)ptr);
        ptr += 2;
        uint8_t reverse_mac[ETHER_ADDR_LEN];
        memcpy(reverse_mac, ptr, ETHER_ADDR_LEN);
        ptr += ETHER_ADDR_LEN; /* should be end of the data */

        if (TLV_PBB_TE_MIP == type) {
            /* validate if the MIP MAC addr field contains an Individual MAC addr */
            if (!ETHER_IS_MCAST(mip_mac_addr)) {
                /* validate if length field is 8 , no Reverse MAC, or is 14,
                contains the Reverse MAC field */
                if ((8 == pbb_te_mip_tlv_length) ||
                    (14 == pbb_te_mip_tlv_length)) {
                    uint8_t *pbb_te_tlv_ptr = lbm_buf + length;
                    /* copy TLV overhead */
                    memcpy(pbb_te_tlv_ptr, &type, 1); /* 1 octet */
                    pbb_te_tlv_ptr += 1;
                    length += 1;
                    memcpy(pbb_te_tlv_ptr, &pbb_te_mip_tlv_length, 2); /* 2 octet */
                    length += 2;
                    pbb_te_tlv_ptr += 2;
                    memcpy(pbb_te_tlv_ptr, mip_mac_addr, ETHER_ADDR_LEN); /* 6 octet */
                    length += ETHER_ADDR_LEN;
                    pbb_te_tlv_ptr += ETHER_ADDR_LEN;
                    memcpy(pbb_te_tlv_ptr, &reverse_vid, 2);
                    length += 2;
                    if (14 == pbb_te_mip_tlv_length) {
                        /* FUTURE_DEVELOPMENT: add validation for group MAC address */
                        if (ETHER_IS_MCAST(reverse_mac)) {
                            memcpy(pbb_te_tlv_ptr, reverse_mac, ETHER_ADDR_LEN);
                            length += ETHER_ADDR_LEN;
                        }
                    }
                }
            }
        }
    }
#endif
    if (NULL != dataTLV) {
        /* ignore the TLV if data type is not 3 */
        uint8_t* ptr = dataTLV;
        uint8_t type = *ptr;
        ptr += 1; /* type is 1 octet long */
        if (TLV_DATA == type) {
            uint16_t data_tlv_length = *((uint16_t*)(ptr));
            ptr += 2; /* length is 2 octet long */
            /* MAX length of PDU is limited to 1492 octets, the maximum length
            value is 1480 (since 12 bytes are required for 8 octets of LBM
            PDU overhead, 3 octets of Data TLV overhead, and 1 octet of End
            TLV). Any other TLVs, if present in LBM, will furthermore detract
            from the maximum length value of 1480 */
            if (PDU_FRAME_LIMIT >= (length + data_tlv_length + TLV_DATA_OVERHEAD)) {
                uint8_t *dataTLV_ptr = lbm_buf + length;
                /* copy TLV overhead */
                memcpy(dataTLV_ptr, &type, 1); /* 1 octet */
                dataTLV_ptr += 1;
                uint16_t length_ntohs = ntohs(data_tlv_length);
                memcpy(dataTLV_ptr, &length_ntohs, 2); /* 2 octet */
                length += TLV_DATA_OVERHEAD;

                dataTLV_ptr += 2;
                memcpy(dataTLV_ptr, ptr, data_tlv_length);
                length += data_tlv_length;
            }
        }
    }

    if (NULL != testTLV) {
        /* ignore the TLV if data type is not 3 */
        uint8_t* ptr = testTLV;
        uint8_t type = *ptr;
        ptr += 1; /* type is 1 octet long */
        if (TLV_TEST_PATTERN == type) {
            uint16_t test_tlv_length = *((uint16_t*)(ptr));
            ptr += 2; /* length is 2 octets long */
            uint8_t pattern_type = *ptr;
            ptr += 1; /* patern type is 1 octet long */

            /* MAX length of PDU is limited to 1492 octets, the maximum length
            value is 1480 (since 12 bytes are required for 8 octets of LBM
            PDU overhead, 3 octets of Data TLV overhead, and 1 octet of End
            TLV). Any other TLVs, if present in LBM, will furthermore detract
            from the maximum length value of 1480. (As one byte is used for
            pattern type, 1479 bytes are available for the test pattern */

            /* +1 octet for pattern type */
            if (PDU_FRAME_LIMIT >= (length + test_tlv_length + TLV_TEST_OVERHEAD + 1)) {
                uint8_t *testTLV_ptr = lbm_buf + length;
                /* copy TLV overhead */
                memcpy(testTLV_ptr, &type, 1); /* 1 octet */
                testTLV_ptr += 1;
                uint16_t length_ntohs = ntohs(test_tlv_length);
                memcpy(testTLV_ptr, &length_ntohs, 2); /* 2 octet */
                length += TLV_TEST_OVERHEAD;
                testTLV_ptr += 2;
                memcpy(testTLV_ptr, &pattern_type, 1); /* 1 octet */
                length += 1;
                testTLV_ptr += 1;
                memcpy(testTLV_ptr, ptr, test_tlv_length);
                length += test_tlv_length;
            }
        }
    }

    /* end packet with End TLV field */
    *(uint8_t *)(lbm_buf + length) = htons(TLV_END);
    length += sizeof(uint8_t);
    return length;
}

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
uint8_t *data_tlv,
uint8_t *test_tlv,
uint8_t *tgt_MAC) {
    if ((NULL == lbm_buf) ||
        (NULL == tgt_MAC)) {
        return 0;
    }
    struct oam_entity_info *entity_db = NULL;
    if (NULL == (entity_db = oam_find_entity_by_mac(tgt_MAC))) {
        struct oam_entity_info new_set;
        memset(&new_set, 0, sizeof(new_set));
        memcpy(new_set.info.mac, tgt_MAC, ETH_MAC_HDR_LENGTH);
        gettimeofday(&new_set.info.lbm_tx_time, NULL);
        /*FUTURE_DEVELOPMENT: find out how we want to create test_seq; a unique ID
        or DB keep a seq number and increase it everytime */
        if (NULL == (entity_db = oam_insert_entity(&new_set)))
        {
            printf("cannot add new entity; discard the message\n");
            return 0;
        }
    }
    return oam_create_eth_lbm(lbm_buf,
        meg_level,
        test_seq,
        pbb_te_mip_tlv,
        data_tlv,
        test_tlv);
}

/**************************************************************************/
/*! \fn processLBR(char *ifname, uint8_t *lbr_frame)
**************************************************************************
*  \brief process the Loopback reply PDU.
*  \param[in] ifname - message receiving interface
*  \param[in] lbr_frame - message buffer including ethernet header
*  \return int 1 (proper ETH-LBR recevied) or 0 (fail)
*/
int
process_lbr(char *ifname, uint8_t *lbr_frame) {
    struct ether_header *lbr_ehdr;
    uint8_t local_mac[ETHER_ADDR_LEN];
    struct cfmhdr *cfmhdr;
    struct cfm_lbr *cfm_lbr;
    struct timeval recv_time;
    uint8_t md_level = 0;

    gettimeofday(&recv_time, NULL);

    if (get_local_mac(ifname, local_mac) != 1) {
        fprintf(stderr, "%s :: Cannot determine local MAC address\n", __func__);
        return 0;
    }
    lbr_ehdr = (struct ether_header *) lbr_frame;

    /* silently discard frame if it was sent by us */
    if (ETHER_IS_EQUAL(lbr_ehdr->ether_shost, local_mac)) {
        return 0;
    }
    /* silently discard frame if destination address does not match
    the MAC address of the receiving MEP */
    if (!ETHER_IS_EQUAL(lbr_ehdr->ether_dhost, local_mac)) {
        return 0;
    }

    cfmhdr = CFMHDR(lbr_frame);

    if (CFM_OPCODE_LBR != cfmhdr->opcode) {
        fprintf(stderr, "%s :: PDU is not ETH_LBR\n", __func__);
        return 0;
    }

    md_level = GET_MD_LEVEL(cfmhdr);
    if (md_level != entity.meg_level)
    {
        fprintf(stderr, "%s :: MEG level is not the same [LBR: %d, entity: %d]\n",
            __func__, md_level, entity.meg_level);
        return 0;
    }

    cfm_lbr = POS_CFM_LBR(lbr_frame);

    /* Y1731 clause 7.2.2.3 */
    /*discard the LBR if received after 5 seconds of transmitting the multicast LBM frame */
    struct oam_entity_info* entity_db = NULL;
    /* only process the lbr from a known responder; known responder == an entity stored in
    database when a LBM is transmitted */
    if (NULL != (entity_db = oam_find_entity_by_mac(lbr_ehdr->ether_shost))) {
        uint32_t deltaTimeSec = (uint32_t)(recv_time.tv_sec - entity_db->info.lbm_tx_time.tv_sec);
        if (LBR_TIMEOUT < deltaTimeSec) {
            fprintf(stderr, "%s :: LBR received later than 5 seconds; LBR discard\n", __func__);
            return 0;
        }
        else
        {
            if (cfm_lbr->transactionID != entity_db->info.lbm_transactionID) {
                fprintf(stderr, "%s :: invalid transactionID received in LBR\n", __func__);
                entity_db->info.lbm_lbr_mismatch += 1;
                return 0;
            }
            /* compare the remembered contents of the corresponding LBM */
            uint8_t *tlv_ptr = ((uint8_t*)cfm_lbr) + sizeof(cfm_lbr);
            uint8_t counter = 0;
            do {
                /* to prevent infinite while loop; the LBM/LBR should only have
                maximum of 2 TLVs (not supporting PBB-TE-MIP.
                If we are looping more than 3 count, we should
                break out from the while loop. */
                /* check the TLV if one exist */
                ++counter;
                switch (*tlv_ptr) {
#if 0 /* this TLV is not support since we are not supporting PBB-TE MIP */
                case TLV_PBB_TE_MIP:
                    --counter; /* reduce the counter if PBB-TE-MIP is included;
                               we should assuming two more TLVs might present. */
                    break;
#endif
                case TLV_DATA:
                {
                                 uint16_t *size = (uint16_t*)(tlv_ptr + 1);
                                 tlv_ptr += TLV_DATA_OVERHEAD;
                                 if (0 != memcmp(entity_db->info.data_tlv, tlv_ptr, ntohs(*size))) {
                                     fprintf(stderr, "%s :: data_tlv does not match with last LBM\n", __func__);
                                     return 0;
                                 }
                                 tlv_ptr += *size;
                }
                    break;
                case TLV_TEST_PATTERN:
                {

                                         uint16_t *size = (uint16_t*)(tlv_ptr + 1);
                                         tlv_ptr += TLV_TEST_OVERHEAD;
                                         if (0 != memcmp(entity_db->info.test_pattern_tlv, tlv_ptr, ntohs(*size))) {
                                             fprintf(stderr, "%s :: test_parttern_tlv does not match with last LBM\n", __func__);
                                             return 0;
                                         }
                                         tlv_ptr += *size;
                }
                    break;
                default:
                    break;
                }
            } while ((TLV_END != *tlv_ptr) && (2 > counter));
        }
    }

    return 1;
}

/**************************************************************************/
/*! \fn oam_create_eth_ltm(uint8_t *ltm_buf,
*                          const uint8_t meg_level,
*                          const uint8_t flag,
*                          struct cfm_ltm *ltm_pdu,
*                          uint8_t *egress_mac))
**************************************************************************
*  \brief create PDU ETH-LTM
*  \param[in] meg_level - entity meg level
*  \param[in] flag - flags for LTM PDU
*  \param[in] ltm_pdu - input value for LTM message
*  \param[in] egress_mac - egress Identifier TLV
*  \param[out] ltm_buf - buffer address after Ethernet header
*  \return int 1 (success) or 0 (fail)
*/
int
oam_create_eth_ltm(uint8_t *ltm_buf,
const uint8_t meg_level,
const uint8_t flag,
struct cfm_ltm* ltm_pdu,
    uint8_t* egress_mac) {
    int32_t length = 0;

    if ((NULL == ltm_buf) ||
        (NULL == ltm_pdu) ||
        (NULL == egress_mac)) {
        return 0;
    }
    /* fill in the common header section */
    cfm_add_hdr(meg_level, flag, FIRST_TLV_LTM, CFM_OPCODE_LTM, ltm_buf);
    length += sizeof(struct cfmhdr);
    struct cfm_ltm *ltm = (struct cfm_ltm*) (ltm_buf + length);
    memcpy(ltm, ltm_pdu, sizeof(struct cfm_ltm));
    length += sizeof(struct cfm_ltm);

    /* add LTM egress Identifier TLV */
    uint8_t *egress_id_tlv = ltm_buf + length;
    /* TLV type 1-octet */
    *egress_id_tlv = TLV_LTM_EGRESS_IDENTIFIER;
    egress_id_tlv += 1;
    length += 1;
    /* length 2-ctets, set to 8 */
    *egress_id_tlv = TLV_LTM_EGRESS_ID_LENGTH;
    egress_id_tlv += 2;
    length += 2;
    /* Egress Identifier */
    /* set Octets 4 and 5 to zeros */
    *egress_id_tlv = 0;
    egress_id_tlv += 1;
    *egress_id_tlv = 0;
    egress_id_tlv += 1;
    /* octets 6-11 contains a 48-bit IEEE MAC addr; where the MEP or
    ETH-LT responder resides (local MAC) */
    memcpy(egress_id_tlv, egress_mac, ETH_MAC_HDR_LENGTH);
    egress_id_tlv += ETH_MAC_HDR_LENGTH;
    length += TLV_LTM_EGRESS_ID_LENGTH;

    /* end packet with End TLV field */
    *(uint8_t *)(ltm_buf + length) = TLV_END;
    length += sizeof(uint8_t);
    return length;
}

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
    uint8_t *egress_mac) {
    if ((NULL == ltm_buf) ||
        (NULL == ltm_pdu) ||
        (NULL == egress_mac)) {
        return 0;
    }
    struct oam_entity_info *entity_db = NULL;
    if (NULL == (entity_db = oam_find_entity_by_mac(ltm_pdu->target_mac))) {
        struct oam_entity_info new_set;
        memset(&new_set, 0, sizeof(new_set));
        memcpy(new_set.info.mac, ltm_pdu->target_mac, ETH_MAC_HDR_LENGTH);

        if (NULL == (entity_db = oam_insert_entity(&new_set)))
        {
            printf("cannot add new entity; discard the message\n");
            return 0;
        }
    }
    return oam_create_eth_ltm(ltm_buf,
        meg_level,
        flag,
        ltm_pdu,
        egress_mac);
}

/**************************************************************************/
/*! \fn open_listen_socket_raw(int* sockFD, char *ifname)
**************************************************************************
*  \brief create an socket for AF_INET and raw socket type.
*  \param[in] ifname - interface name which bind to the socket
*  \param[out] sockFD -  raw socket
*  \return int 1 (success) or 0 (fail)
*/
int open_listen_socket_raw(int* sockFD, char *ifname) {
    struct ifreq ifopts; /* interface option */
    struct sockaddr_ll sll;
#ifdef L2VPN_SUPPORT
    int optval = 1;
#endif

    memset(&ifopts, 0, sizeof(ifopts));
    *sockFD = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (-1 == *sockFD) {
        fprintf(stderr, "%s : open socket failed\n", __func__);
        return 0;
    }

#ifdef L2VPN_SUPPORT
    if (entity.sa_index_filter) {
        setsockopt(*sockFD, SOL_PACKET, TI_AUXDATA, &optval, sizeof optval);
    }
#endif

    strncpy(ifopts.ifr_name, ifname, sizeof(ifopts.ifr_name) - 1);
    ioctl(*sockFD, SIOCGIFFLAGS, &ifopts);
    /* find the interface index */
    if (-1 == ioctl(*sockFD, SIOCGIFINDEX, &ifopts)) {
        fprintf(stderr, "%s : find interface index failed\n", __func__);
        return 0;
    }

    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifopts.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    /* bind the raw socket to the interface */
    if (-1 == bind(*sockFD, (struct sockaddr*) &sll, sizeof(sll))) {
        fprintf(stderr, "%s : bind socket failed\n", __func__);
        return 0;
    }
    return 1;
}

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
int receive_msg(int *socketFD, uint8_t* buf, size_t buf_size, int* msg_size) {

    struct msghdr msghdr;
    struct iovec iov[1];
    struct sockaddr_ll from;
    struct ether_header *eh = (struct ether_header *) buf;
    int flag = 0,
        rc = 0;
    void * msg_control = NULL;
    int msg_controllen = 0;
#ifdef L2VPN_SUPPORT
    char control[CMSG_SPACE(sizeof(struct ti_auxdata))];
#endif

    if ((NULL == socketFD) || (NULL == buf) || (NULL == msg_size))
    {
        return rc;
    }
    memset(&from, 0, sizeof(from));
    memset(iov, 0, sizeof(iov));
    memset(&msghdr, 0, sizeof(msghdr));
    iov[0].iov_base = (char*)buf;
    iov[0].iov_len = buf_size;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_name = (void *)&from;
    msghdr.msg_namelen = sizeof(from);
    msghdr.msg_flags = 0;
#ifdef L2VPN_SUPPORT
    msg_control = (void *)control;
    msg_controllen = sizeof(control);
#endif
    msghdr.msg_control = msg_control;
    msghdr.msg_controllen = msg_controllen;

    *msg_size = recvmsg(*socketFD, &msghdr, flag);

    if (ETHER_MIN_LEN <= *msg_size) {
        int etherType = ntohs(eh->ether_type);
        if ((ETH_P_8021Q == etherType) || (ETH_P_CFM == etherType)) {
            rc = 1;
        }
    }

#ifdef L2VPN_SUPPORT
    /* Receive downstream TI metadata */
    if (rc && entity.sa_index_filter) {
        struct cmsghdr *cmsg;
        struct ti_auxdata *ti_aux_local;

        for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {

            if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == TI_AUXDATA) {

                ti_aux_local = (struct ti_auxdata *) CMSG_DATA(cmsg);

                if (!ti_aux_local) {
                    perror("Received NULL pointer to cmsg TI_AUXDATA");
                    rc = 0;
                }
                else{
                    /* Filter on SA index */
                    if (entity.sa_index_filter) {
                        int counter = 0, match = 0;
                        int sa_index = ti_aux_local->ti_meta_info2 & L2VPN_RELATED_SAID_MASK;

                        for (counter = 0; counter<entity.sa_index_count; counter++) {
                            if (entity.sa_index[counter] == sa_index) {
                                match++;
                            }
                        }

                        /* If we didn't match the SAID index, return failure */
                        if (!match) {
                            rc = 0;
                        }
                    }
                }

                break;
            }
        }

    }
#endif

    return rc;
}

