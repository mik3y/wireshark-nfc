/* packet-llcp.c
 * Dissector routines for NFC Forum NFC Data Exchange Format (NDEF), v1.0
 * Author: Steven Cary <stevec@google.com>
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

void proto_reg_handoff_ndef(void);

static const value_string tnf_field_value_names[] = {
	{ 0x00, "Empty" },
	{ 0x01, "NFC Forum well-known type [NFC RTD]" },
	{ 0x02, "Media-type as defined in RFC 2046 [RFC 2046]" },
	{ 0x03, "Absolute URI as defined in RFC 3986 [RFC 3986]" },
	{ 0x04, "NFC Forum external type [NFC RTD]" },
	{ 0x05, "Unknown" },
	{ 0x06, "Unchanged" },
	{ 0x07, "Reserved" },
	{ 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_ndef = -1;
static int hf_ndef_record = -1;

/* NDEF Record */
static int hf_ndef_record_mb = -1;
static int hf_ndef_record_me = -1;
static int hf_ndef_record_cf = -1;
static int hf_ndef_record_sr = -1;
static int hf_ndef_record_il = -1;
static int hf_ndef_record_tnf = -1;
static int hf_ndef_record_type_length = -1;
static int hf_ndef_record_payload_length = -1;
static int hf_ndef_record_payload_length_sr = -1;
static int hf_ndef_record_id_length = -1;
static int hf_ndef_record_type = -1;
static int hf_ndef_record_id = -1;
static int hf_ndef_record_payload = -1;

/* Initialize the subtree pointers */
static gint ett_ndef = -1;
static gint ett_ndef_record = -1;

#define NDEF_SHORT_RECORD_MIN_LEN 5
#define NDEF_STANDARD_RECORD_MIN_LEN 7
#define SR_BIT_OFFSET 3  // From beginning of packet.
#define IL_BIT_OFFSET 4  // From beginning of packet.


static int
dissect_ndef_record(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *ndef_record_tree;
	guint8 sr;
	guint8 il;
	guint8 type_length;
	guint payload_length;
	guint id_length;
	guint offset;

	if (tvb_length(tvb) < NDEF_STANDARD_RECORD_MIN_LEN)
		return 0;  // XXX Error.
	
	sr = tvb_get_bits8(tvb, SR_BIT_OFFSET, 1);
	il = tvb_get_bits8(tvb, IL_BIT_OFFSET, 1);

	if (tree) {
		ti = proto_tree_add_item(tree, hf_ndef_record, tvb, 0, -1,
			ENC_BIG_ENDIAN);

		ndef_record_tree = proto_item_add_subtree(ti, ett_ndef_record);

		offset = 0;

		proto_tree_add_item(ndef_record_tree,
		    hf_ndef_record_mb, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ndef_record_tree,
		    hf_ndef_record_me, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ndef_record_tree,
		    hf_ndef_record_cf, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ndef_record_tree,
		    hf_ndef_record_sr, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ndef_record_tree,
		    hf_ndef_record_il, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ndef_record_tree,
		    hf_ndef_record_tnf, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		type_length = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ndef_record_tree,
		    hf_ndef_record_type_length, tvb, offset, 1,
		    ENC_BIG_ENDIAN);
		offset += 1;

		if (sr == 1) {
			payload_length = tvb_get_guint8(tvb, offset);
			// MUST be 1, can check here.
			proto_tree_add_item(ndef_record_tree,
			    hf_ndef_record_payload_length_sr, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
			offset += 1;
		} else {
			payload_length = tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(ndef_record_tree,
			    hf_ndef_record_payload_length, tvb, offset, 4,
			    ENC_BIG_ENDIAN);
			offset += 4;
		}
		if (il != 0) {
			id_length = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(ndef_record_tree,
			    hf_ndef_record_id_length, tvb, offset, 1,
			    ENC_BIG_ENDIAN);
			offset += 1;
		} else {
			id_length = 0; // default.
		}

		if (type_length > 0) {
			// TODO(stevec): Decode common types.
			proto_tree_add_item(ndef_record_tree,
			    hf_ndef_record_type, tvb, offset, type_length,
			    ENC_BIG_ENDIAN);
			offset += 1;
		}
		
		if (id_length > 0) {
			proto_tree_add_item(ndef_record_tree,
			    hf_ndef_record_id, tvb, offset, id_length,
			    ENC_BIG_ENDIAN);
			offset += 1;
		}

		if (payload_length > 0) {
			proto_tree_add_item(ndef_record_tree,
			    hf_ndef_record_payload, tvb, offset,
			    payload_length,
			    ENC_NA);
		}
	}

	return tvb_length(tvb);
}

/* Code to actually dissect the packets */
static int
dissect_ndef(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	proto_item *sub_tree;
	proto_tree *ndef_tree;
	tvbuff_t *next_tvb;

	offset = 0;

	if (tvb_length(tvb) < NDEF_SHORT_RECORD_MIN_LEN) {
		return offset;
	}

	#if 0  // TODO(stevec): More errors.
	if (tvb_get_guint8(tvb, 0, 1) != 0) {
		if (tvb_length(tvb) < NDEF_STANDARD_RECORD_MIN_LEN)
			return 0;
	}
	#endif

	if (tree) {
		sub_tree = proto_tree_add_item(tree, proto_ndef, tvb, 0, -1,
		ENC_BIG_ENDIAN);

		ndef_tree = proto_item_add_subtree(sub_tree, ett_ndef);

		next_tvb = tvb_new_subset(tvb, offset, -1, -1);
		while (tvb_length(next_tvb) > 0) {
			// TODO(stevec): check again for minimum length
			// TODO(stevec): Test multiple records...
			offset += dissect_ndef_record(next_tvb, pinfo,
				ndef_tree);
			next_tvb = tvb_new_subset(tvb, offset, -1, -1);
		}
	}

	return offset;
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/
void
proto_register_ndef(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_ndef_record,
			{ "NDEF Record", "ndef.record", FT_BYTES, BASE_NONE,
			NULL, 0, "An NDEF Record", HFILL }},
		{ &hf_ndef_record_mb,
			{ "Message Begin", "ndef.record.mb", FT_BOOLEAN, 8,
			NULL, 0x80, "Indicates the start of an NDEF message",
			HFILL }},
		{ &hf_ndef_record_me,
			{ "Message End", "ndef.record.me", FT_BOOLEAN, 8, NULL,
			0x40, "Indicates the end of an NDEF message", HFILL }},
		{ &hf_ndef_record_cf,
			{ "Chunk Flag", "ndef.record.cf", FT_BOOLEAN, 8, NULL,
			0x20,
			"Record is first chunk or a middle chunk of a chunked \
			payload", HFILL }},
		{ &hf_ndef_record_sr,
			{ "Short Record", "ndef.record.sr", FT_BOOLEAN, 8,
			NULL, 0x10, "Record is a short record", HFILL }},
		{ &hf_ndef_record_il,
			{ "ID Length Present", "ndef.record.il", FT_BOOLEAN, 8,
			NULL, 0x08, "ID_LENGTH field is present in record",
			HFILL }},
		{ &hf_ndef_record_tnf,
			{ "Type Name Format", "ndef.record.tnf", FT_UINT8,
			BASE_HEX, tnf_field_value_names, 0x07,
			"The structure of the value of the Type field",
			HFILL }},
		{ &hf_ndef_record_type_length,
			{ "Type Length", "ndef.record.type_length", FT_UINT8,
			BASE_DEC, NULL, 0, "Length of the Type field",
			HFILL }},
		{ &hf_ndef_record_payload_length,
			{ "Payload Length", "ndef.record.payload_length",
			FT_UINT32, BASE_DEC, NULL, 0,
			"The length of the payload", HFILL }},
		{ &hf_ndef_record_payload_length_sr,
			{ "Payload Length", "ndef.record.payload_length",
			FT_UINT8, BASE_DEC, NULL, 0,
			"The length of the payload", HFILL }},
		{ &hf_ndef_record_id_length,
			{ "ID Length", "ndef.record.id_length",
			FT_UINT8, BASE_DEC, NULL, 0,
			"The length of the ID field", HFILL }},
		{ &hf_ndef_record_type,
			{ "Type", "ndef.record.type",
			FT_BYTES, BASE_NONE, NULL, 0, "Record type",
			HFILL }},
		{ &hf_ndef_record_id,
			{ "ID", "ndef.record.id",
			FT_BYTES, BASE_NONE, NULL, 0, "Record ID",
			HFILL }},
		{ &hf_ndef_record_payload,
			{ "Payload", "ndef.record.payload",
			FT_BYTES, BASE_NONE, NULL, 0, "Record payload",
			HFILL }},
	};

	static gint *ett[] = {
		&ett_ndef,
		&ett_ndef_record
	};

	proto_ndef = proto_register_protocol("NDEF Message",
	    "NDEF", "ndef");

	proto_register_field_array(proto_ndef, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ndef(void)
{
	dissector_handle_t ndef_handle;
	ndef_handle = new_create_dissector_handle(dissect_ndef, proto_ndef);
	heur_dissector_add("snep.ndef", dissect_ndef, proto_ndef);
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
