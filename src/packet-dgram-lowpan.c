/*
 * packet-dgram-lowpan.c
 *
 *  Created on: 09.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */
#include "packet-dgram-lowpan.h"

#include <wireshark/config.h>
#include <epan/packet.h>
#include <glib.h>

#include <epan/dissectors/packet-ieee802154.h>

static dissector_handle_t data_handle;
static dissector_handle_t ipnd_handle;

static int proto_dgram_lowpan = -1;
static int hf_dgram_lowpan_seqno = -1;
static int hf_dgram_lowpan_first_frame = -1;
static int hf_dgram_lowpan_last_frame = -1;

static gint ett_dgram = -1;
static gint ett_dgram_frame = -1;

#define DGRAM_FRAME_BEACON 0x02
#define DGRAM_FRAME_DATA 0x01
#define DGRAM_FRAME_ACK 0x03
#define DGRAM_FRAME_NACK 0x00

#define DGRAM_FRAME_SEQNO_MASK 0x0C
#define DGRAM_FRAME_TYPE_MASK 0x30
#define DGRAM_FRAME_FIRST_MASK 0x02
#define DGRAM_FRAME_LAST_MASK 0x01

static const value_string frame_type_vals[] = {
    {DGRAM_FRAME_DATA, "Data"},
    {DGRAM_FRAME_BEACON, "Beacon"},
    {DGRAM_FRAME_ACK, "Ack"},
    {DGRAM_FRAME_NACK, "Nack"},
    {0, NULL}
};

static void        dissect_dgram_lowpan     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void        dissect_dgram_lowpan_fh  (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);

static void        proto_init_dgram_lowpan        (void);
void               proto_register_dgram_lowpan    (void);
void               proto_reg_handoff_dgram_lowpan (void);

static void
dissect_dgram_lowpan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *payload_tvb = NULL;

	// set protocol name
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LowPAN Datagram");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) { /* we are being asked for details */
		proto_item *proto_root = NULL;
		proto_tree *dgram_tree = NULL;

		guint offset = 0;

		proto_root = proto_tree_add_protocol_format(tree, proto_dgram_lowpan, tvb, 0, tvb_captured_length(tvb), "LowPAN Datagram");
		dgram_tree = proto_item_add_subtree(proto_root, ett_dgram);

		// get the type byte
		const char type_value = tvb_get_guint8(tvb, offset);

		// dissect frame header
		dissect_dgram_lowpan_fh(tvb, pinfo, dgram_tree, &offset);

		switch (type_value & DGRAM_FRAME_TYPE_MASK) {
		case DGRAM_FRAME_BEACON << 4:
			// dissect beacon
			payload_tvb = tvb_new_subset_remaining(tvb, offset);

			// call data dissector with remaining data
			call_dissector(ipnd_handle, payload_tvb, pinfo, tree);
			break;
		case DGRAM_FRAME_DATA << 4:
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
dissect_dgram_lowpan_fh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *dgram_tree = NULL;

		// get the header byte
		const char header = tvb_get_guint8(tvb, *offset);

		// get frame type name as string
		const char *type_name = val_to_str_const((header >> 4) & 0x03, frame_type_vals, "Unknown");

		// set column info text
		col_set_str(pinfo->cinfo, COL_INFO, type_name);

		// set frame type name in protocol tree name
		proto_item_append_text(tree, " %s", type_name);

		// add new sub-tree
		dgram_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 1, ett_dgram_frame, &ti, "Frame Header: %s (0x%02x)", type_name, (header >> 4) & 0x03);

		// sequence number
		proto_tree_add_item(dgram_tree, hf_dgram_lowpan_seqno, tvb, *offset, 1, ENC_NA);

		// first frame
		proto_tree_add_item(dgram_tree, hf_dgram_lowpan_first_frame, tvb, *offset, 1, ENC_NA);

		// last frame
		proto_tree_add_item(dgram_tree, hf_dgram_lowpan_last_frame, tvb, *offset, 1, ENC_NA);

		if ((header & DGRAM_FRAME_TYPE_MASK) != (DGRAM_FRAME_BEACON << 4)) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ", Seqno: %d", (header & DGRAM_FRAME_SEQNO_MASK) >> 2);
			proto_item_append_text(tree, ", Seqno: %d", (header & DGRAM_FRAME_SEQNO_MASK) >> 2);
		}
	}

	// move offset ahead of the header
	(*offset)++;
}

static gboolean
dissect_dgram_lowpan_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	const char header = tvb_get_guint8(tvb, 0);

	/** dissect the frames **/
	if ((header && (0x03 << 6)) > 0) {
		dissect_dgram_lowpan(tvb, pinfo, tree);
		return TRUE;
	}

	return FALSE;
}

void
proto_register_dgram_lowpan(void)
{
	static hf_register_info hf[] = {
		{ &hf_dgram_lowpan_seqno,
			{ "Sequence number", "dgram.seqno",
				FT_UINT8, BASE_DEC, NULL, DGRAM_FRAME_SEQNO_MASK, NULL, HFILL }
		},
		{ &hf_dgram_lowpan_first_frame,
			{ "First Frame", "dgram.first",
				FT_BOOLEAN, 8, NULL, DGRAM_FRAME_FIRST_MASK, NULL, HFILL }
		},
		{ &hf_dgram_lowpan_last_frame,
			{ "Last Frame", "dgram.last",
				FT_BOOLEAN, 8, NULL, DGRAM_FRAME_LAST_MASK, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_dgram,
		&ett_dgram_frame,
	};

	register_init_routine(proto_init_dgram_lowpan);

	proto_dgram_lowpan = proto_register_protocol(
		"LowPAN Datagram Protocol", /* name */
		"DGRAM LowPAN", /* short name */
		DGRAM_PROTOABBREV_LOWPAN /* abbrev */
	);

	proto_register_field_array(proto_dgram_lowpan, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/*  Register dissectors with Wireshark. */
	register_dissector(DGRAM_PROTOABBREV_LOWPAN, dissect_dgram_lowpan, proto_dgram_lowpan);
}

void
proto_reg_handoff_dgram_lowpan(void)
{
    static gboolean            prefs_initialized = FALSE;
    static dissector_handle_t  dgram_handle;
    static unsigned int        old_dgram_ethertype;

	if (!prefs_initialized){
		/* Get the dissector handles. */
		dgram_handle   = create_dissector_handle(dissect_dgram_lowpan, proto_dgram_lowpan);
		data_handle    = find_dissector("data");
		ipnd_handle    = find_dissector("ipnd");
		prefs_initialized = TRUE;
	} else {
		// Nothing to deregister.
		heur_dissector_delete(IEEE802154_PROTOABBREV_WPAN, dissect_dgram_lowpan_heur, proto_dgram_lowpan);
	}

	/* Register our dissector with IEEE 802.15.4 */
	heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_dgram_lowpan_heur, "IPND over WPAN", "ipnd_wpan", proto_dgram_lowpan, HEURISTIC_ENABLE);
}

static void
proto_init_dgram_lowpan(void)
{
}
