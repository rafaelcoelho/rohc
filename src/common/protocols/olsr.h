/*
 * olsr.h
 *
 *  Created on: Jul 22, 2016
 *      Author: rscoelho
 */

#ifndef SRC_COMMON_PROTOCOLS_OLSR_H_
#define SRC_COMMON_PROTOCOLS_OLSR_H_

#include <stdint.h>

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif

struct olsrhdr
{
#if WORDS_BIGENDIAN == 1
        uint16_t packet_length;
        uint16_t packet_seq_number;
        uint16_t message_type:8;
        uint16_t vtime:8;
        uint16_t message_size;
        uint32_t originator_addr;
        uint16_t time_to_live:8;
        uint16_t hop_count:8;
#else
        uint16_t packet_length;
        uint16_t packet_seq_number;
        uint16_t vtime:8;
        uint16_t message_type:8;
        uint16_t message_size;
        uint32_t originator_addr;
        uint16_t hop_count:8;
        uint16_t time_to_live:8;
#endif
        uint16_t messsage_seq_number;
} __attribute__((packed));

#endif /* SRC_COMMON_PROTOCOLS_OLSR_H_ */
