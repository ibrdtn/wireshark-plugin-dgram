/*
 * packet-dgram-beacon.h
 *
 *  Created on: 10.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */

#include <wireshark/config.h>
#include <epan/packet.h>

#ifndef PACKET_DGRAM_BEACON_H_
#define PACKET_DGRAM_BEACON_H_

#define BEACON_CONTAINS_EID 0x01
#define BEACON_CONTAINS_SERVICE_BLOCK 0x02
#define BEACON_CONTAINS_BLOOMFILTER 0x04

#define SDNV_MASK       0x7f

int evaluate_sdnv(tvbuff_t *tvb, int offset, int *bytecount);

#endif /* PACKET_DGRAM_BEACON_H_ */
