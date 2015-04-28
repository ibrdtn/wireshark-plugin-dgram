/*
 * packet-dtn-ipnd.c
 *
 *  Created on: 17.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */

#include "packet-dtn-ipnd.h"

#include <wireshark/config.h>
#include <epan/wmem/wmem.h>
#include <epan/packet.h>
#include <glib.h>

static int proto_dtn_ipnd = -1;

static int hf_dtn_ipnd_version = -1;
static int hf_dtn_ipnd_contains_eid = -1;
static int hf_dtn_ipnd_contains_service_block = -1;
static int hf_dtn_ipnd_contains_bloomfilter = -1;
static int hf_dtn_ipnd_sn = -1;
static int hf_dtn_ipnd_endpoint = -1;

static gint ett_dtn_ipnd = -1;

static guint dtn_ipnd_port = 4551;

static void        dissect_dtn_ipnd     (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void        proto_init_dtn_ipnd          (void);
void               proto_register_dtn_ipnd      (void);
void               proto_reg_handoff_dtn_ipnd   (void);


static void
dissect_dtn_ipnd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int         sdnv_length;
	int         endpoint_length;
	guint8      flags;
	int         offset;

	// set protocol name
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPND");

	// set info text
	col_set_str(pinfo->cinfo, COL_INFO, "Beacon");

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *ipnd_tree = NULL;
		offset = 0;

		// add new sub-tree
		ti = proto_tree_add_text(tree, tvb, offset, -1, "IP Neighbor Discovery Beacon");
		ipnd_tree = proto_item_add_subtree(ti, ett_dtn_ipnd);

		// version
		proto_tree_add_item(ipnd_tree, hf_dtn_ipnd_version, tvb, offset, 1, ENC_BIG_ENDIAN);

		// move offset pointer to the flags
		offset++;

		// flags
		flags = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ipnd_tree, hf_dtn_ipnd_contains_eid, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ipnd_tree, hf_dtn_ipnd_contains_service_block, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ipnd_tree, hf_dtn_ipnd_contains_bloomfilter, tvb, offset, 1, ENC_BIG_ENDIAN);

		// move offset pointer to the sequence number
		offset++;

		// sequence number
		proto_tree_add_item(ipnd_tree, hf_dtn_ipnd_sn, tvb, offset, 2, ENC_BIG_ENDIAN);

		// move offset pointer ahead of the static header
		offset += 2;

		// decode EID if present
		if (flags & IPND_CONTAINS_EID)
		{
			endpoint_length = evaluate_sdnv(tvb, offset, &sdnv_length);
			offset += sdnv_length;

			if (endpoint_length > 0) {
				// add endpoint to info text
				col_append_fstr(pinfo->cinfo, COL_INFO, ", Endpoint: %s", tvb_get_string_enc(wmem_packet_scope(),tvb, offset, endpoint_length,ENC_ASCII));

				/*
				 * Endpoint name may not be null terminated. This routine is supposed
				 * to add the null at the end of the string buffer.
				 */
				proto_tree_add_item(ipnd_tree, hf_dtn_ipnd_endpoint, tvb, offset, endpoint_length, ENC_NA|ENC_ASCII);
				offset += endpoint_length;
			}
		}
	}
}

void
proto_register_dtn_ipnd(void)
{
	static hf_register_info hf[] = {
		{ &hf_dtn_ipnd_version,
			{ "Version", "ipnd.version",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{&hf_dtn_ipnd_contains_eid,
			{"Contains Endpoint ID", "ipnd.contains_eid",
				 FT_BOOLEAN, 8, NULL, IPND_CONTAINS_EID, NULL, HFILL}
		},
		{&hf_dtn_ipnd_contains_service_block,
			{"Contains Service Block", "ipnd.contains_service_block",
				FT_BOOLEAN, 8, NULL, IPND_CONTAINS_SERVICE_BLOCK, NULL, HFILL}
		},
		{&hf_dtn_ipnd_contains_bloomfilter,
			{"Contains Bloom Filter", "ipnd.contains_bloomfilter",
				 FT_BOOLEAN, 8, NULL, IPND_CONTAINS_BLOOMFILTER, NULL, HFILL}
		},
		{ &hf_dtn_ipnd_sn,
			{ "Sequence number", "ipnd.sn",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_dtn_ipnd_endpoint,
			{ "Endpoint", "ipnd.endpoint",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_dtn_ipnd,
	};

	register_init_routine(proto_init_dtn_ipnd);

	proto_dtn_ipnd = proto_register_protocol(
		"IP Neighbor Discovery", /* name */
		"IPND", /* short name */
		DTN_PROTOABBREV_IPND /* abbrev */
	);

	proto_register_field_array(proto_dtn_ipnd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/*  Register dissectors with Wireshark. */
	register_dissector(DTN_PROTOABBREV_IPND, dissect_dtn_ipnd, proto_dtn_ipnd);
}

void
proto_reg_handoff_dtn_ipnd(void)
{
    static gboolean            prefs_initialized = FALSE;
    static dissector_handle_t  dgram_handle;
    static guint udp_port;

	if (!prefs_initialized){
		/* Get the dissector handles. */
		dgram_handle   = create_dissector_handle(dissect_dtn_ipnd, proto_dtn_ipnd);
		prefs_initialized = TRUE;
	} else {
		dissector_delete_uint("udp.port", udp_port, dgram_handle);
	}

	udp_port = dtn_ipnd_port;

	dissector_add_uint("udp.port", udp_port, dgram_handle);
}

static void
proto_init_dtn_ipnd(void)
{
}

/*3rd arg is number of bytes in field (returned)*/
int
evaluate_sdnv(tvbuff_t *tvb, int offset, int *bytecount)
{
    int    value = 0;
    guint8 curbyte;

    *bytecount = 0;

    /*
     * Get 1st byte and continue to get them while high-order bit is 1
     */

    while ((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK) {
        if (*bytecount >= (int) sizeof(int)) {
            *bytecount = 0;
            return -1;
        }
        value = value << 7;
        value |= (curbyte & SDNV_MASK);
        ++offset;
        ++*bytecount;
    }

    /*
     * Add in the byte whose high-order bit is 0 (last one)
     */

    value = value << 7;
    value |= (curbyte & SDNV_MASK);
    ++*bytecount;
    return value;
}
