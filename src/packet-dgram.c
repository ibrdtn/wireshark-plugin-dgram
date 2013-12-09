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

#include <epan/dissectors/packet-ieee802154.h>
#include <epan/dissectors/packet-dtn.h>

static dissector_handle_t data_handle;

static int proto_dgram = -1;
static int hf_dgram_frame_type = -1;
static int hf_dgram_seqno = -1;
static int hf_dgram_first_frame = -1;
static int hf_dgram_last_frame = -1;
static gint ett_dgram = -1;

static const value_string frame_type_vals[] = {
    {0x01, "Data"},
    {0x02, "Beacon"},
    {0x03, "Ack"},
    {0x00, "Nack"},
    {0, NULL}
};

static void        dissect_dgram            (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void        proto_init_dgram         (void);
void               proto_register_dgram     (void);
void               proto_reg_handoff_dgram  (void);

static void
dissect_dgram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *payload_tvb = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DGRAM LowPAN");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *dgram_tree = NULL;

		ti = proto_tree_add_item(tree, proto_dgram, tvb, 0, -1, ENC_NA);
		dgram_tree = proto_item_add_subtree(ti, ett_dgram);

		// type header
		proto_tree_add_item(dgram_tree, hf_dgram_frame_type, tvb, 0, 1, ENC_NA);

		// sequence number
		proto_tree_add_item(dgram_tree, hf_dgram_seqno, tvb, 0, 1, ENC_NA);

		// first frame
		proto_tree_add_item(dgram_tree, hf_dgram_first_frame, tvb, 0, 1, ENC_NA);

		// last frame
		proto_tree_add_item(dgram_tree, hf_dgram_last_frame, tvb, 0, 1, ENC_NA);

		// info text
		const char header = tvb_get_guint8(tvb, 0);
		col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const((header >> 4) & 0x03, frame_type_vals, "Unknown"));

		payload_tvb = tvb_new_subset_remaining(tvb, 1);

		// call data dissector with remaining data
		call_dissector(data_handle, payload_tvb, pinfo, tree);
	}
}

static gboolean
dissect_dgram_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	const char header = tvb_get_guint8(tvb, 0);

	/** dissect the frames **/
	if ((header && (0x03 << 6)) > 0) {
		dissect_dgram(tvb, pinfo, tree);
		return TRUE;
	}

	return FALSE;
}

void
proto_register_dgram(void)
{
	static hf_register_info hf[] = {
		{ &hf_dgram_frame_type,
			{ "Frame Type", "dgram.type",
				FT_UINT8, BASE_DEC, VALS(frame_type_vals), (0x03 << 4), NULL, HFILL }
		},
		{ &hf_dgram_seqno,
			{ "Sequence number", "dgram.seqno",
				FT_UINT8, BASE_DEC, NULL, (0x03 << 2), NULL, HFILL }
		},
		{ &hf_dgram_first_frame,
			{ "First Frame", "dgram.first",
				FT_BOOLEAN, 8, NULL, (0x02), NULL, HFILL }
		},
		{ &hf_dgram_last_frame,
			{ "Last Frame", "dgram.last",
				FT_BOOLEAN, 8, NULL, (0x01), NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_dgram
	};

	register_init_routine(proto_init_dgram);

	proto_dgram = proto_register_protocol(
		"LowPAN Datagram Protocol", /* name */
		"dgram:lowpan", /* short name */
		IEEE802154_PROTOABBREV_DGRAM /* abbrev */
	);

    proto_register_field_array(proto_dgram, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

	/*  Register dissectors with Wireshark. */
	register_dissector(IEEE802154_PROTOABBREV_DGRAM, dissect_dgram, proto_dgram);
}

void
proto_reg_handoff_dgram(void)
{
    static gboolean            prefs_initialized = FALSE;
    static dissector_handle_t  dgram_handle;
    static unsigned int        old_dgram_ethertype;

	if (!prefs_initialized){
		/* Get the dissector handles. */
		dgram_handle   = create_dissector_handle(dissect_dgram, proto_dgram);
		data_handle    = find_dissector("data");
		prefs_initialized = TRUE;
	} else {
		// Nothing to deregister.
		heur_dissector_delete(IEEE802154_PROTOABBREV_WPAN, dissect_dgram_heur, proto_dgram);
	}

	/* Register our dissector with IEEE 802.15.4 */
	heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_dgram_heur, proto_dgram);
}

static void
proto_init_dgram(void)
{
}
