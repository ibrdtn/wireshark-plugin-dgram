/*
 * packet-dgram-udp.c
 *
 *  Created on: 09.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */
#include "packet-dgram-udp.h"
#include "packet-dgram-beacon.h"

#include <wireshark/config.h>
#include <epan/packet.h>
#include <glib.h>

static dissector_handle_t data_handle;

static int proto_dgram_udp = -1;

static int hf_dgram_udp_seqno = -1;
static int hf_dgram_udp_first_frame = -1;
static int hf_dgram_udp_last_frame = -1;

static int hf_dgram_beacon_version = -1;
static int hf_dgram_beacon_contains_eid = -1;
static int hf_dgram_beacon_contains_service_block = -1;
static int hf_dgram_beacon_contains_bloomfilter = -1;
static int hf_dgram_beacon_sn = -1;
static int hf_dgram_beacon_endpoint = -1;

static gint ett_dgram = -1;
static gint ett_dgram_frame = -1;
static gint ett_dgram_beacon = -1;

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
static void        dissect_dgram_udp_beacon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset);

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
			dissect_dgram_udp_beacon(tvb, pinfo, dgram_tree, &offset);
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

/** parse the beacon frame **/
static void
dissect_dgram_udp_beacon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset)
{
	int         sdnv_length;
	int         endpoint_length;
	guint8      flags;

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *beacon_tree = NULL;

		// add new sub-tree
		ti = proto_tree_add_text(tree, tvb, *offset, -1, "Neighbor Discovery Beacon");
		beacon_tree = proto_item_add_subtree(ti, ett_dgram_beacon);

		// version
		proto_tree_add_item(beacon_tree, hf_dgram_beacon_version, tvb, *offset, 1, ENC_BIG_ENDIAN);

		// move offset pointer to the flags
		(*offset)++;

		// flags
		flags = tvb_get_guint8(tvb, *offset);
		proto_tree_add_item(beacon_tree, hf_dgram_beacon_contains_eid, tvb, *offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(beacon_tree, hf_dgram_beacon_contains_service_block, tvb, *offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(beacon_tree, hf_dgram_beacon_contains_bloomfilter, tvb, *offset, 1, ENC_BIG_ENDIAN);

		// move offset pointer to the sequence number
		(*offset)++;

		// sequence number
		proto_tree_add_item(beacon_tree, hf_dgram_beacon_sn, tvb, *offset, 2, ENC_BIG_ENDIAN);

		// move offset pointer ahead of the static header
		(*offset) += 2;

		// decode EID if present
		if (flags & BEACON_CONTAINS_EID)
		{
			endpoint_length = evaluate_sdnv(tvb, *offset, &sdnv_length);
			(*offset) += sdnv_length;

			if (endpoint_length > 0) {
				// add endpoint to info text
				col_append_fstr(pinfo->cinfo, COL_INFO, ", Endpoint: %s", tvb_get_string(tvb, *offset, endpoint_length));

				/*
				 * Endpoint name may not be null terminated. This routine is supposed
				 * to add the null at the end of the string buffer.
				 */
				proto_tree_add_item(beacon_tree, hf_dgram_beacon_endpoint, tvb, *offset, endpoint_length, ENC_NA|ENC_ASCII);
				(*offset) += endpoint_length;
			}
		}
	}
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
		},
		{ &hf_dgram_beacon_version,
			{ "Version", "dgram.beacon.version",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{&hf_dgram_beacon_contains_eid,
			{"Contains Endpoint ID", "dgram.beacon.contains_eid",
				 FT_BOOLEAN, 8, NULL, BEACON_CONTAINS_EID, NULL, HFILL}
		},
		{&hf_dgram_beacon_contains_service_block,
			{"Contains Service Block", "dgram.beacon.contains_service_block",
				FT_BOOLEAN, 8, NULL, BEACON_CONTAINS_SERVICE_BLOCK, NULL, HFILL}
		},
		{&hf_dgram_beacon_contains_bloomfilter,
			{"Contains Bloom Filter", "dgram.beacon.contains_bloomfilter",
				 FT_BOOLEAN, 8, NULL, BEACON_CONTAINS_BLOOMFILTER, NULL, HFILL}
		},
		{ &hf_dgram_beacon_sn,
			{ "Sequence number", "dgram.beacon.sn",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dgram_beacon_endpoint,
			{ "Endpoint", "dgram.beacon.endpoint",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_dgram,
		&ett_dgram_frame,
		&ett_dgram_beacon,
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
