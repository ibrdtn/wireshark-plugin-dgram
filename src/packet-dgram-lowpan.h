/*
 * packet-dgram-lowpan.h
 *
 *  Created on: 09.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */

#ifndef PACKET_DGRAM_LOWPAN_H_
#define PACKET_DGRAM_LOWPAN_H_

/* Protocol Abbreviation */
#define DGRAM_PROTOABBREV_LOWPAN     "dgram.lowpan"

void proto_register_dgram_lowpan(void);
void proto_reg_handoff_dgram_lowpan(void);

#endif /* PACKET_DGRAM_LOWPAN_H_ */
