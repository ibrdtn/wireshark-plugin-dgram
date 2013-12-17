/*
 * packet-dgram-udp.c
 *
 *  Created on: 09.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */
#include "packet-dgram-udp.h"

#include <wireshark/config.h>
#include <epan/packet.h>
#include <glib.h>

static dissector_handle_t data_handle;
static dissector_handle_t ipnd_handle;

static int proto_dgram_udp = -1;

static int hf_dgram_udp_seqno = -1;
static int hf_dgram_udp_first_frame = -1;
static int hf_dgram_udp_last_frame = -1;

static gint ett_dgram = -1;
static gint ett_dgram_frame = -1;

static guint dgram_udp_port = 4554;
static guint dgram_beacon_udp_port = 5551;

#define DGRAM_FRAME_BEACON 0x01
#define DGRAM_FRAME_DATA 0x02
#define DGRAM_FRAME_ACK 0x04
#define DGRAM_FRAME_NACK 0x08

#define DGRAM_FRAME_SEQNO_MASK 0x0f
#define DGRAM_FRAME_FIRST_MASK 0x20
#define DGRAM_FRAME_LAST_MASK 0x10

static const value_string frame_type_vals[] = {
    {DGRAM_FRAME_DATA, "Data"},
    {DGRAM_FRAME_BEACON, "Beacon"},
    {DGRAM_FRAME_ACK, "Ack"},
    {DGRAM_FRAME_NACK, "Nack"},
    {0, NULL}
};

static void        dissect_dgram_udp     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void        dissect_dgram_udp_fh  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);

static void        proto_init_dgram_udp         (void);
void               proto_register_dgram_udp     (void);
void               proto_reg_handoff_dgram_udp  (void);

static void
dissect_dgram_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *payload_tvb = NULL;

	// set protocol name
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDP Datagram");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) { /* we are being asked for details */
		proto_item *proto_root = NULL;
		proto_tree *dgram_tree = NULL;

		guint offset = 0;

		proto_root = proto_tree_add_protocol_format(tree, proto_dgram_udp, tvb, 0, tvb_length(tvb), "UDP Datagram");
		dgram_tree = proto_item_add_subtree(proto_root, ett_dgram);

		// get the type byte
		const char type_value = tvb_get_guint8(tvb, offset);

		// dissect frame header
		dissect_dgram_udp_fh(tvb, pinfo, dgram_tree, &offset);

		switch (type_value) {
		case DGRAM_FRAME_BEACON:
			// dissect beacon
			payload_tvb = tvb_new_subset_remaining(tvb, offset);

			// call data dissector with remaining data
			call_dissector(ipnd_handle, payload_tvb, pinfo, tree);
			break;
		case DGRAM_FRAME_DATA:
			payload_tvb = tvb_new_subset_remaining(tvb, offset);

			// call data dissector with remaining data
			call_dissector(data_handle, payload_tvb, pinfo, tree);
			break;
		default:
			break;
		}
	}
}

/** parse the frame header **/
static void
dissect_dgram_udp_fh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *dgram_tree = NULL;

		// get the type byte
		const char type_value = tvb_get_guint8(tvb, *offset);

		// get frame type name as string
		const char *type_name = val_to_str_const(type_value, frame_type_vals, "Unknown");

		// set column info text
		col_set_str(pinfo->cinfo, COL_INFO, type_name);

		// set frame type name in protocol tree name
		proto_item_append_text(tree, " %s", type_name);

		// add new sub-tree
		ti = proto_tree_add_text(tree, tvb, *offset, 1, "Frame Header: %s (0x%02x)", type_name, type_value);
		dgram_tree = proto_item_add_subtree(ti, ett_dgram_frame);

		// get the flags/seqno byte
		const char flags_seqno = tvb_get_guint8(tvb, (*offset) + 1);

		// first frame
		proto_tree_add_item(dgram_tree, hf_dgram_udp_first_frame, tvb, (*offset) + 1, 1, ENC_NA);

		// last frame
		proto_tree_add_item(dgram_tree, hf_dgram_udp_last_frame, tvb, (*offset) + 1, 1, ENC_NA);

		// sequence number
		proto_tree_add_item(dgram_tree, hf_dgram_udp_seqno, tvb, (*offset) + 1, 1, ENC_NA);

		if (type_value != DGRAM_FRAME_BEACON) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ", Seqno: %d", flags_seqno & 0x0f);
			proto_item_append_text(tree, ", Seqno: %d", flags_seqno & 0x0f);
		}
	}

	// move offset ahead of the header
	(*offset) += 2;
}

void
proto_register_dgram_udp(void)
{
	static hf_register_info hf[] = {
		{ &hf_dgram_udp_first_frame,
			{ "First Frame", "dgram.first",
				FT_BOOLEAN, 8, NULL, DGRAM_FRAME_FIRST_MASK, NULL, HFILL }
		},
		{ &hf_dgram_udp_last_frame,
			{ "Last Frame", "dgram.last",
				FT_BOOLEAN, 8, NULL, DGRAM_FRAME_LAST_MASK, NULL, HFILL }
		},
		{ &hf_dgram_udp_seqno,
			{ "Sequence number", "dgram.seqno",
				FT_UINT8, BASE_DEC, NULL, DGRAM_FRAME_SEQNO_MASK, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_dgram,
		&ett_dgram_frame,
	};

	register_init_routine(proto_init_dgram_udp);

	proto_dgram_udp = proto_register_protocol(
		"UDP Datagram Protocol", /* name */
		"DGRAM UDP", /* short name */
		DGRAM_PROTOABBREV_UDP /* abbrev */
	);

	proto_register_field_array(proto_dgram_udp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/*  Register dissectors with Wireshark. */
	register_dissector(DGRAM_PROTOABBREV_UDP, dissect_dgram_udp, proto_dgram_udp);
}

void
proto_reg_handoff_dgram_udp(void)
{
    static gboolean            prefs_initialized = FALSE;
    static dissector_handle_t  dgram_handle;
    static guint udp_port;
    static guint udp_beacon_port;

	if (!prefs_initialized){
		/* Get the dissector handles. */
		dgram_handle   = create_dissector_handle(dissect_dgram_udp, proto_dgram_udp);
		data_handle    = find_dissector("data");
		ipnd_handle    = find_dissector("ipnd");
		prefs_initialized = TRUE;
	} else {
		dissector_delete_uint("udp.port", udp_port, dgram_handle);
		dissector_delete_uint("udp.port", udp_beacon_port, dgram_handle);
	}

	udp_port = dgram_udp_port;
	udp_beacon_port = dgram_beacon_udp_port;

	dissector_add_uint("udp.port", udp_port, dgram_handle);
	dissector_add_uint("udp.port", udp_beacon_port, dgram_handle);
}

static void
proto_init_dgram_udp(void)
{
}
