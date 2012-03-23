/* packet-snep.c
 * Dissector routines for NFC Forum Simple NDEF Exchange Protocol (SNEP), v1.1
 * Author: mike wakerly <mikey@google.com>
 *
 * Copyright 2012 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_reg_handoff_snep(void);

/* Initialize the protocol and registered fields */
static int proto_snep = -1;
static int hf_snep_version = -1;
static int hf_snep_type = -1;
static int hf_snep_length = -1;
static int hf_snep_info = -1;

static int hf_snep_acceptable_length = -1;
static int hf_snep_ndef = -1;

/* Initialize the subtree pointers */
static gint ett_snep = -1;
static gint ett_snep_information = -1;

static heur_dissector_list_t heur_subdissector_list;

#define SNEP_HEADER_LENGTH 6
#define SNEP_VERSION 0x10

#define SNEP_DEFAULT_SAP 4

#define SNEP_REQUEST_CONTINUE 0x00
#define SNEP_REQUEST_GET 0x01
#define SNEP_REQUEST_PUT 0x02
#define SNEP_REQUEST_REJECT 0x7f

#define SNEP_RESPONSE_CONTINUE 0x80
#define SNEP_RESPONSE_SUCCESS 0x81
#define SNEP_RESPONSE_NOT_FOUND 0xc0
#define SNEP_RESPONSE_EXCESS_DATA 0xc1
#define SNEP_RESPONSE_BAD_REQUEST 0xc2
#define SNEP_RESPONSE_NOT_IMPLEMENTED 0xe0
#define SNEP_RESPONSE_UNSUPPORTED 0xe1
#define SNEP_RESPONSE_REJECT 0xff

static const value_string snep_type_vs[] = {
	{ SNEP_REQUEST_CONTINUE, "Req: Continue" },
	{ SNEP_REQUEST_GET, "Req: Get" },
	{ SNEP_REQUEST_PUT, "Req: Put" },
	{ SNEP_REQUEST_REJECT, "Req: Reject" },

	{ SNEP_RESPONSE_CONTINUE, "Res: Continue" },
	{ SNEP_RESPONSE_SUCCESS, "Res: Success" },
	{ SNEP_RESPONSE_NOT_FOUND, "Res: Not Found" },
	{ SNEP_RESPONSE_EXCESS_DATA, "Res: Excess Data" },
	{ SNEP_RESPONSE_BAD_REQUEST, "Res: Bad Request" },
	{ SNEP_RESPONSE_NOT_IMPLEMENTED, "Res: Not Implemented" },
	{ SNEP_RESPONSE_UNSUPPORTED, "Res: Unsupported" },
	{ SNEP_RESPONSE_REJECT, "Res: Reject" },
	{ 0, NULL }
};

/* Formatter for hf_snep_version using BASE_CUSTOM */
static void snep_version_str(gchar* buf, guint32 value) {
	g_snprintf(buf, ITEM_LABEL_LENGTH, "%d.%d", (value >> 4) & 0xf, value & 0xf);
}

static int snep_dissect_payload(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, gint8 request_type) {
	switch (request_type) {
		case SNEP_REQUEST_GET:
			if (tvb_length(tvb) < 4) {
				// TODO(mikey): add malformed packet error
				return 0;
			}
			proto_tree_add_item(tree, hf_snep_acceptable_length,
					tvb, 0, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_snep_ndef, tvb, 4, -1, ENC_NA);
			break;
		case SNEP_REQUEST_PUT:
			if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree)){
				return tvb_length(tvb);
			} else {
				proto_tree_add_item(tree, hf_snep_ndef, tvb, 0, -1, ENC_NA);
			}
			break;
		default:
			break;
	}
	return 0;
}

/* Code to actually dissect the packets */
static int
dissect_snep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *snep_tree;

	/* SNEP Header fields */
	guint8 version;
	guint8 request_type;
	guint32 length;

	/* Check that there's enough data */
	/* Maximum length is 2**32 - 1 */
	if (tvb_length(tvb) < SNEP_HEADER_LENGTH) {
		return 0;
	}

	version = tvb_get_guint8(tvb, 0);
	request_type = tvb_get_guint8(tvb, 1);
	length = tvb_get_ntohl(tvb, 2);

	#if 0
	if (version != SNEP_VERSION) {
		return 0;
	}
	#endif

	/* TODO(mikey): validate request types. */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SNEP");
	col_set_str(pinfo->cinfo, COL_INFO, val_to_str(request_type, snep_type_vs, "Unknown"));

	if (tree) {
		guint offset;
		guint info_len;

		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_snep, tvb, 0, -1, ENC_NA);
		snep_tree = proto_item_add_subtree(ti, ett_snep);

		offset = 0;
		proto_tree_add_item(snep_tree, hf_snep_version, tvb, offset, 1,
				ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(snep_tree, hf_snep_type, tvb, offset, 1,
				ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(snep_tree, hf_snep_length, tvb, offset, 4,
				ENC_BIG_ENDIAN);
		offset += 4;

		info_len = tvb_length(tvb) - offset;
		if (info_len > 0) {
			tvbuff_t *next_tvb;
			proto_item *sub_tree;
			proto_tree *payload_tree;

			next_tvb = tvb_new_subset_remaining(tvb, offset);

			sub_tree = proto_tree_add_item(snep_tree, hf_snep_info, next_tvb, 0, -1, ENC_NA);
			payload_tree = proto_item_add_subtree(sub_tree, ett_snep_information);

			snep_dissect_payload(pinfo, next_tvb, payload_tree, request_type);
		}
	}

	/* Return the amount of data this dissector was able to dissect */
	return tvb_length(tvb);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_snep(void)
{
	module_t *snep_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_snep_version,
			{ "Version", "snep.version",
				FT_UINT8, BASE_CUSTOM, snep_version_str, 0xff,
				"Protocol version", HFILL }
		},
		{ &hf_snep_type,
			{ "Type", "snep.type",
				FT_UINT8, BASE_HEX, VALS(snep_type_vs), 0xff,
				"Message type", HFILL }
		},
		{ &hf_snep_length,
			{ "Length", "snep.length",
				FT_UINT32, BASE_DEC, NULL, 0xffffffff,
				"Payload length", HFILL }
		},
		{ &hf_snep_info,
			{ "Info", "snep.info",
				FT_BYTES, BASE_NONE, NULL, 0,
				"Message body", HFILL }
		},
		{ &hf_snep_acceptable_length,
			{ "Acceptable Length", "snep.acceptable_length",
				FT_UINT32, BASE_DEC, NULL, 0,
				"Acceptable length", HFILL }
		},
		{ &hf_snep_ndef,
			{ "NDEF Message", "snep.ndef",
				FT_BYTES, BASE_NONE, NULL, 0,
				"NDEF message", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_snep,
		&ett_snep_information,
	};

	/* Register the protocol name and description */
	proto_snep = proto_register_protocol("Simple NDEF Messaging Protocol", "SNEP", "snep");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_snep, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_heur_dissector_list("snep.ndef", &heur_subdissector_list);

	/* Register preferences module (See Section 2.6 for more on preferences) */
	snep_module = prefs_register_protocol(proto_snep, NULL);
}
void
proto_reg_handoff_snep(void)
{
	dissector_handle_t snep_handle;
	snep_handle = new_create_dissector_handle(dissect_snep, proto_snep);
	dissector_add_uint("llcp.sap", SNEP_DEFAULT_SAP, snep_handle);

	/* TODO(mikey): register as heuristic detector if we need to later. */
	/* heur_dissector_add("llcp", dissect_snep, proto_snep); */
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
