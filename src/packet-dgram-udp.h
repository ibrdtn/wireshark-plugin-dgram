/*
 * packet-dgram-udp.h
 *
 *  Created on: 09.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */

#ifndef PACKET_DGRAM_UDP_H_
#define PACKET_DGRAM_UDP_H_

/* Protocol Abbreviation */
#define DGRAM_PROTOABBREV_UDP     "dgram.udp"

void proto_register_dgram_udp(void);
void proto_reg_handoff_dgram_udp(void);

#endif /* PACKET_DGRAM_UDP_H_ */
