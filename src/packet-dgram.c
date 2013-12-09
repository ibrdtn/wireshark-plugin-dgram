/*
 * packet-dgram.c
 *
 *  Created on: 09.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */
#include "packet-dgram.h"

#include <wireshark/config.h>
#include <epan/packet.h>
#include <glib.h>

static int proto_dgram = -1;

static int hf_dgram_pdu_type = -1;

static gint ett_dgram = -1;

/* Forward declaration we need below (if using proto_reg_handoff...
   as a prefs callback)       */
void proto_reg_handoff_dgram(void);

static void dissect_dgram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DGRAM");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *dgram_tree = NULL;

		ti = proto_tree_add_item(tree, proto_dgram, tvb, 0, -1, ENC_NA);
		dgram_tree = proto_item_add_subtree(ti, ett_dgram);
		proto_tree_add_item(dgram_tree, hf_dgram_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);
	}
}

void proto_register_dgram(void)
{
	static hf_register_info hf[] = {
		{ &hf_dgram_pdu_type,
			{ "DGRAM PDU Type", "dgram.type",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_dgram
	};

	proto_dgram = proto_register_protocol(
		"IBR-DTN Datagram Protocol", /* name */
		"DGRAM:LOWPAN", /* short name */
		"dgram" /* abbrev */
	);

	/*  Register dissectors with Wireshark. */
	register_dissector("dgram", dissect_dgram, proto_dgram);
}

void proto_reg_handoff_dgram(void)
{
	static dissector_handle_t dgram_handle;

	dgram_handle = create_dissector_handle(dissect_dgram, proto_dgram);
	dissector_add_string("frame.protocols", "wpan:data", dgram_handle);
}
