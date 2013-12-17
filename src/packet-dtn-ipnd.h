/*
 * packet-dtn-ipnd.h
 *
 *  Created on: 17.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */

#include <wireshark/config.h>
#include <epan/packet.h>

#ifndef PACKET_DTN_IPND_H_
#define PACKET_DTN_IPND_H_

/* Protocol Abbreviation */
#define DTN_PROTOABBREV_IPND     "ipnd"

#define IPND_CONTAINS_EID 0x01
#define IPND_CONTAINS_SERVICE_BLOCK 0x02
#define IPND_CONTAINS_BLOOMFILTER 0x04

#define SDNV_MASK       0x7f

int evaluate_sdnv(tvbuff_t *tvb, int offset, int *bytecount);

void proto_register_dtn_ipnd(void);
void proto_reg_handoff_dtn_ipnd(void);


#endif /* PACKET_DTN_IPND_H_ */
