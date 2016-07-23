/*
 * c_olsr.c
 *
 *  Created on: Jul 22, 2016
 *      Author: rscoelho
 */

#include "c_olsr.h"
#include "c_udp.h"
#include "rohc_traces_internal.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "sdvl.h"
#include "crc.h"
#include "rohc_comp_rfc3095.h"

#include <stdlib.h>
#ifndef __KERNEL__
#  include <string.h>
#endif
#include <assert.h>

static bool c_olsr_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
        __attribute__((warn_unused_result, nonnull(1, 2)));
static void c_olsr_destroy(struct rohc_comp_ctxt *const context)
        __attribute__((nonnull(1)));

static bool c_olsr_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
        __attribute__((warn_unused_result, nonnull(1, 2)));

static bool c_olsr_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
        __attribute__((warn_unused_result, nonnull(1, 2), pure));

static int c_olsr_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
        __attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

static int olsr_changed_olsr_dynamic(const struct rohc_comp_ctxt *const context,
                                    const struct udphdr *const udp,
                                    const struct olsrhdr *const olsr);

static bool c_olsr_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
{
        struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
        const struct udphdr *udp;
        const struct olsrhdr *olsr;

        assert(context != NULL);
        assert(context->profile != NULL);

        //TODO: Check ROHC_LSB_SHIFT_IP_ID
        /* create and initialize the generic part of the profile context */
        if(!rohc_comp_rfc3095_create(context, ROHC_LSB_SHIFT_IP_ID, packet))
        {
                rohc_comp_warn(context, "generic context creation failed");
                goto quit;
        }
        rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

        /* check that transport protocol is UDP, and application protocol is OLSR */
        assert(packet->transport->proto == ROHC_IPPROTO_UDP);
        assert(packet->transport->data != NULL);
        udp = (struct udphdr *) packet->transport->data;
        olsr = (struct olsrhdr *) (udp + 1);

        /* initialize SN with the SN found in the olsr header */
        rfc3095_ctxt->sn = (uint32_t) rohc_ntoh16(olsr->packet_seq_number);
        assert(rfc3095_ctxt->sn <= 0xffff);
        rohc_comp_debug(context, "initialize context(SN) = hdr(SN) of first "
                        "packet = %u", rfc3095_ctxt->sn);

        clean:
                rohc_comp_rfc3095_destroy(context);
        quit:
                return false;
}

static void c_olsr_destroy(struct rohc_comp_ctxt *const context)
{
        struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
        struct sc_olsr_context *olsr_context;

        assert(context != NULL);
        assert(context->specific != NULL);
        rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
        assert(rfc3095_ctxt->specific != NULL);
        olsr_context = (struct sc_olsr_context *) rfc3095_ctxt->specific;

        //TODO: Check
//        c_destroy_sc(&olsr_context->ts_sc);
        c_destroy_wlsb(rfc3095_ctxt->sn_window);
        rohc_comp_rfc3095_destroy(context);
}

static bool c_olsr_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
{
        const struct udphdr *udp_header;
        const uint8_t *udp_payload;
        unsigned int udp_payload_size;
        bool udp_check;

        /* check that:
         *  - the transport protocol is UDP,
         *  - that the versions of outer and inner IP headers are 4 or 6,
         *  - that outer and inner IP headers are not IP fragments,
         *  - the IP payload is at least 8-byte long for UDP header,
         *  - the UDP Length field and the UDP payload match.
         */
        udp_check = c_udp_check_profile(comp, packet);
        if(!udp_check)
        {
                goto bad_profile;
        }

        /* retrieve the UDP header and the UDP payload */
        assert(packet->transport->proto == ROHC_IPPROTO_UDP);
        assert(packet->transport->data != NULL);
        udp_header = (const struct udphdr *) packet->transport->data;
        udp_payload = (uint8_t *) (udp_header + 1);
        udp_payload_size = packet->transport->len - sizeof(struct udphdr);

        /* UDP payload shall be large enough for olsr header  */
        if(udp_payload_size < sizeof(struct olsrhdr))
        {
                goto bad_profile;
        }

        bad_profile:
                return false;
}

static bool c_olsr_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
{
        const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
                (struct rohc_comp_rfc3095_ctxt *) context->specific;
        const struct sc_olsr_context *const olsr_context =
                (struct sc_olsr_context *) rfc3095_ctxt->specific;
        const struct udphdr *const udp = (struct udphdr *) packet->transport->data;
        const struct olsrhdr *const olsr = (struct olsrhdr *) (udp + 1);
        bool udp_check;

        /* check IP and UDP headers */
        udp_check = c_udp_check_context(context, packet);
        if(!udp_check)
        {
                goto bad_context;
        }

        return true;

bad_context:
        return false;
}

static int c_olsr_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
{
        struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
        struct sc_olsr_context *olsr_context;
        const struct udphdr *udp;
        const struct olsrhdr *olsr;
        int size;

        assert(context != NULL);
        assert(context->specific != NULL);
        rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
        assert(rfc3095_ctxt->specific != NULL);
        olsr_context = (struct sc_olsr_context *) rfc3095_ctxt->specific;

        /* retrieve the UDP and olsr headers */
        assert(uncomp_pkt->transport->data != NULL);
        udp = (struct udphdr *) uncomp_pkt->transport->data;
        olsr = (struct olsrhdr *) (udp + 1);

        /*TODO: Check how many UDP/OLSR fields changed? */
        /*olsr_context->tmp.send_olsr_dynamic = olsr_changed_olsr_dynamic(context, udp, olsr);*/

        /* encode the IP packet */
        size = rohc_comp_rfc3095_encode(context, uncomp_pkt, rohc_pkt, rohc_pkt_max_len,
                                        packet_type, payload_offset);
        if(size < 0)
        {
                goto quit;
        }

        /* update the context with the new UDP/olsr headers */
        if(rfc3095_ctxt->tmp.packet_type == ROHC_PACKET_IR ||
           rfc3095_ctxt->tmp.packet_type == ROHC_PACKET_IR_DYN)
        {
                memcpy(&olsr_context->old_udp, udp, sizeof(struct udphdr));
                /*memcpy(&olsr_context->old_udpold_olsr, olsr, sizeof(struct olsrhdr));TODO: remove*/
        }
        else
        {
//                if(olsr_context->tmp.padding_bit_changed) TODO: check
//                {
//                        olsr_context->old_olsr.padding = olsr->padding;
//                }
//                if(olsr_context->tmp.extension_bit_changed)
//                {
//                        olsr_context->old_olsr.extension = olsr->extension;
//                }
        }

        quit:
        return size;
}


static int olsr_changed_olsr_dynamic(const struct rohc_comp_ctxt *const context,
                                    const struct udphdr *const udp,
                                    const struct olsrhdr *const olsr)
{
        struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
        struct sc_olsr_context *olsr_context;
        int fields = 0;

        rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
        olsr_context = (struct sc_olsr_context *) rfc3095_ctxt->specific;

        rohc_comp_debug(context, "find changes in olsr dynamic fields");

        /* check UDP checksum field */
        if((udp->check != 0 && olsr_context->old_udp.check == 0) ||
           (udp->check == 0 && olsr_context->old_udp.check != 0) /*||
           (olsr_context->udp_checksum_change_count < MAX_IR_COUNT)TODO: check*/)
        {
                if((udp->check != 0 && olsr_context->old_udp.check == 0) ||
                   (udp->check == 0 && olsr_context->old_udp.check != 0))
                {
                        rohc_comp_debug(context, "UDP checksum field changed");
                        /*olsr_context->udp_checksum_change_count = 0; TODO: check*/
                }
                else
                {
                        rohc_comp_debug(context, "UDP checksum field did not change but "
                                        "changed in the last few packets");
                }

                /* do not count the UDP checksum change as other olsr dynamic fields
                 * because it requires a specific behaviour (IR or IR-DYN packet
                 * required). */
        }

        return fields;
}

const struct rohc_comp_profile c_olsr_profileggggg =
{
        .id             = ROHC_PROFILE_OLSR, /* profile ID */
        .protocol       = ROHC_IPPROTO_UDP, /* IP protocol */
        .create         = c_olsr_create,     /* profile handlers */
        .destroy        = c_olsr_destroy,
        .check_profile  = c_olsr_check_profile,
        .check_context  = c_olsr_check_context,
        .encode         = c_olsr_encode,
        .reinit_context = rohc_comp_reinit_context,
        .feedback       = rohc_comp_rfc3095_feedback,
};
