/* packet-llcp.c
 * Dissector routines for NFC Forum Logical Link Control Protocol (LLCP), v1.1
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

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#include <wiretap/wtap.h>

void proto_reg_handoff_llcp(void);

/* Initialize the protocol and registered fields */
static int proto_llcp = -1;
static int proto_llcpip = -1;

static int hf_llcp_dsap = -1;
static int hf_llcp_ptype = -1;
static int hf_llcp_ssap = -1;
static int hf_llcp_seqn = -1;

static int hf_llcp_info = -1;
static int hf_llcp_info_params = -1;
static int hf_llcp_info_subframes = -1;

static int hf_llcp_frmr_w = -1;
static int hf_llcp_frmr_i = -1;
static int hf_llcp_frmr_r = -1;
static int hf_llcp_frmr_s = -1;
static int hf_llcp_frmr_ptype = -1;
static int hf_llcp_frmr_seqn = -1;
static int hf_llcp_frmr_vs = -1;
static int hf_llcp_frmr_vr = -1;
static int hf_llcp_frmr_vsa = -1;
static int hf_llcp_frmr_vra = -1;

static int hf_llcp_reason = -1; /* DM */

#define PORT_LLCP 7739
static guint global_llcp_udp_port = PORT_LLCP;
static guint global_llcp_tcp_port = PORT_LLCP;

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;

/* Initialize the subtree pointers */
static gint ett_llcp = -1;
static gint ett_llcp_info = -1;
static gint ett_llcp_info_params = -1;
static gint ett_llcp_info_subframes = -1;

#define LLCP_HEADER_MIN_LENGTH 2
#define LLCP_VERSION 0x10

#define LLCP_PTYPE_SYMM 0
#define LLCP_PTYPE_PAX 1
#define LLCP_PTYPE_AGF 2
#define LLCP_PTYPE_UI 3
#define LLCP_PTYPE_CONNECT 4
#define LLCP_PTYPE_DISC 5
#define LLCP_PTYPE_CC 6
#define LLCP_PTYPE_DM 7
#define LLCP_PTYPE_FRMR 8
#define LLCP_PTYPE_SNL 9
#define LLCP_PTYPE_I 12
#define LLCP_PTYPE_RR 13
#define LLCP_PTYPE_RNR 14

static const value_string llcp_ptype_vs[] = {
	{ LLCP_PTYPE_SYMM, "Symmetry (SYMM)" },
	{ LLCP_PTYPE_PAX, "Parameter Exchange (PAX)" },
	{ LLCP_PTYPE_AGF, "Aggregated Frame (AGF)" },
	{ LLCP_PTYPE_UI, "Unnumbered Information (UI)" },
	{ LLCP_PTYPE_CONNECT, "Connect (CONNECT)" },
	{ LLCP_PTYPE_DISC, "Disconnect (DISC)" },
	{ LLCP_PTYPE_CC, "Connection Complete (CC)" },
	{ LLCP_PTYPE_DM, "Disconnected Mode (DM)" },
	{ LLCP_PTYPE_FRMR, "Frame Reject (FRMR)" },
	{ LLCP_PTYPE_SNL, "Service Name Lookup (SNL)" },
	{ LLCP_PTYPE_I, "Information (I)" },
	{ LLCP_PTYPE_RR, "Receive Ready (RR)" },
	{ LLCP_PTYPE_RNR, "Receive Not Ready (RNR)" },
	{ 0, NULL }
};

static const value_string llcp_dm_reason_vs[] = {
	{ 0x00, "Normal disconnect" },
	{ 0x01, "No active connection for connection-oriented PDU at SAP" },
	{ 0x02, "No service bound to target SAP" },
	{ 0x03, "CONNECT PDU rejected by service layer" },
	{ 0x10, "Permanent failure for target SAP" },
	{ 0x11, "Permanent failure for any target SAP" },
	{ 0x20, "Temporary failure for target SAP" },
	{ 0x21, "Temporary failure for any target SAP" },
	{ 0, NULL }
};

enum llcp_param_t {
	LLCP_PARAM_VERSION = 1,
	LLCP_PARAM_MIUX,
	LLCP_PARAM_WKS,
	LLCP_PARAM_LTO,
	LLCP_PARAM_RW,
	LLCP_PARAM_SN,
	LLCP_PARAM_OPT,
	LLCP_PARAM_SDREQ,
	LLCP_PARAM_SDRES,
	LLCP_PARAM_MAX
};

static const value_string llcp_parameter_vs[] = {
	{ LLCP_PARAM_VERSION, "Version Number" },
	{ LLCP_PARAM_MIUX, "Maximum Information Unit Extensions" },
	{ LLCP_PARAM_WKS, "Well-Known Service List" },
	{ LLCP_PARAM_LTO, "Link Timeout" },
	{ LLCP_PARAM_RW, "Receive Window Size" },
	{ LLCP_PARAM_SN, "Service Name" },
	{ LLCP_PARAM_OPT, "Option" },
	{ LLCP_PARAM_SDREQ, "Service Discovery Request" },
	{ LLCP_PARAM_SDRES, "Service Discovery Response" },
	{ 0, NULL }
};

enum llcp_wks_t {
	LLCP_WKS_1 = 1,
	LLCP_WKS_2,
	LLCP_WKS_3,
	LLCP_WKS_4,
	LLCP_WKS_5,
	LLCP_WKS_6,
	LLCP_WKS_7,
	LLCP_WKS_8,
	LLCP_WKS_9,
	LLCP_WKS_10,
	LLCP_WKS_11,
	LLCP_WKS_12,
	LLCP_WKS_13,
	LLCP_WKS_14,
	LLCP_WKS_15,
	LLCP_WKS_MAX
};

static int hf_llcp_info_param[LLCP_PARAM_MAX];
static int hf_llcp_info_param_wks[LLCP_WKS_MAX];

static int llcp_dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_llcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Formatter for hf_llcp_version using BASE_CUSTOM */
static void llcp_version_str(gchar* buf, guint32 value) {
	g_snprintf(buf, ITEM_LABEL_LENGTH, "%d.%d", (value >> 4) & 0xf, value & 0xf);
}

#define ADDR_MAX_LEN 32
static void llcp_set_address(packet_info* pinfo, guint8 ssap, guint8 dsap) {
	char* src_addr;
	char* dst_addr;
	guint8 adapter;
	guint8 flags;

	src_addr = ep_alloc(ADDR_MAX_LEN);
	dst_addr = ep_alloc(ADDR_MAX_LEN);

	pinfo->srcport = ssap;
	pinfo->destport = dsap;

	adapter = pinfo->pseudo_header->llcp.adapter;
	flags = pinfo->pseudo_header->llcp.flags;

	if (flags & (1 << LLCP_PHDR_FLAG_SENT)) {
		g_snprintf(src_addr, ADDR_MAX_LEN, "adapter%d:0x%02x", adapter, ssap);
		g_snprintf(dst_addr, ADDR_MAX_LEN, "remote:0x%02x", dsap);
	} else {
		g_snprintf(src_addr, ADDR_MAX_LEN, "remote:0x%02x", ssap);
		g_snprintf(dst_addr, ADDR_MAX_LEN, "adapter%d:0x%02x", adapter, dsap);
	}

	SET_ADDRESS(&pinfo->src, AT_STRINGZ, (int) strlen(src_addr) + 1, src_addr);
	SET_ADDRESS(&pinfo->dst, AT_STRINGZ, (int) strlen(dst_addr) + 1, dst_addr);
}
#undef ADDR_MAX_LEN

static int llcp_dissect_info_param(tvbuff_t *tvb, proto_tree *tree) {
	guint8 type;
	guint8 len;
	guint32 tvb_len;
	guint32 offset;

	offset = 0;
	tvb_len = tvb_length(tvb);

	type = tvb_get_guint8(tvb, offset++);
	len = tvb_get_guint8(tvb, offset++);

	if ((len + offset) > tvb_len) {
		// TODO(mikey): error?
		return offset;
	}

	switch (type) {
		case LLCP_PARAM_VERSION:
		case LLCP_PARAM_LTO:
		case LLCP_PARAM_RW:
		case LLCP_PARAM_OPT:
			proto_tree_add_item(tree, hf_llcp_info_param[type], tvb, offset, 1,
					ENC_BIG_ENDIAN);
			offset++;
			break;
		case LLCP_PARAM_MIUX:
			proto_tree_add_item(tree, hf_llcp_info_param[LLCP_PARAM_MIUX], tvb, offset, 2,
					ENC_BIG_ENDIAN);
			offset += 2;
			break;
		case LLCP_PARAM_WKS: {
			int i;
			guint16 wks_list;

			wks_list = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(tree, hf_llcp_info_param[LLCP_PARAM_WKS], tvb, offset, 2,
					ENC_BIG_ENDIAN);

			for (i = LLCP_WKS_1; i < LLCP_WKS_MAX; i++) {
				if (wks_list & (1 << i)) {
					proto_tree_add_item(tree, hf_llcp_info_param_wks[i], tvb, offset, 2,
							ENC_BIG_ENDIAN);
				}
			}
			offset += 2;
			break;
		}
		default:
			break;
	}
	return offset;
}

static int llcp_dissect_info_subframes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	guint32 offset;
	guint32 tvb_len;

	tvb_len = tvb_length(tvb);
	offset = 0;

	while (tvb_len - offset >= 2) {
		guint32 frame_len;

		frame_len = tvb_get_guint8(tvb, offset++);
		if ((offset + frame_len) > tvb_len) {
			/* TODO(mikey): error */
			break;
		}

		llcp_dissect_frame(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
		offset += frame_len;
	}
	return tvb_len;
}

/* llcp_dissect_info_params
 * Extract the "parameter list".
 */
static int llcp_dissect_info_params(tvbuff_t *tvb, proto_tree *tree) {
	guint32 offset;
	guint32 tvb_len;

	tvb_len = tvb_length(tvb);
	offset = 0;

	while (tvb_len - offset >= 2) {
		guint32 amt;

		amt = llcp_dissect_info_param(tvb_new_subset_remaining(tvb, offset), tree);
		offset += amt;
	}
	return tvb_len;
}

static int llcp_dissect_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint8 ptype) {
	guint8 ssap;
	guint8 dsap;

	ssap = pinfo->srcport;
	dsap = pinfo->destport;

	switch (ptype) {
		case LLCP_PTYPE_UI:
		case LLCP_PTYPE_I:
			if (dissector_try_uint(subdissector_table, dsap, tvb, pinfo, tree)) {
				return tvb_length(tvb);
			} else if (dissector_try_uint(subdissector_table, ssap, tvb, pinfo, tree)) {
				return tvb_length(tvb);
			} else if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree)){
				return tvb_length(tvb);
			}
			break;
		case LLCP_PTYPE_DM:
			proto_tree_add_item(tree, hf_llcp_reason, tvb, 0, 1, ENC_BIG_ENDIAN);
			break;
		case LLCP_PTYPE_PAX:
		case LLCP_PTYPE_CONNECT:
		case LLCP_PTYPE_CC:
		case LLCP_PTYPE_SNL: {
			/* Parameter list. */
			proto_item *sub_tree;
			proto_tree *param_tree;

			sub_tree = proto_tree_add_item(tree, hf_llcp_info_params, tvb, 0, -1, ENC_NA);
			param_tree = proto_item_add_subtree(sub_tree, ett_llcp_info_params);

			llcp_dissect_info_params(tvb, param_tree);
			break;
		}
		case LLCP_PTYPE_AGF: {
			/* Aggregated frame. */
			proto_item *sub_tree;
			proto_tree *frame_tree;

			sub_tree = proto_tree_add_item(tree, hf_llcp_info_subframes, tvb, 0, -1, ENC_NA);
			frame_tree = proto_item_add_subtree(sub_tree, ett_llcp_info_subframes);

			llcp_dissect_info_subframes(tvb, pinfo, frame_tree);
			break;
		}
		case LLCP_PTYPE_FRMR:
			proto_tree_add_item(tree, hf_llcp_frmr_w, tvb, 0, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_llcp_frmr_i, tvb, 0, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_llcp_frmr_r, tvb, 0, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_llcp_frmr_s, tvb, 0, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_llcp_frmr_ptype, tvb, 0, 1, ENC_BIG_ENDIAN);

			proto_tree_add_item(tree, hf_llcp_frmr_seqn, tvb, 1, 1, ENC_BIG_ENDIAN);

			proto_tree_add_item(tree, hf_llcp_frmr_vs, tvb, 2, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_llcp_frmr_vr, tvb, 2, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_llcp_frmr_vsa, tvb, 2, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_llcp_frmr_vra, tvb, 2, 2, ENC_BIG_ENDIAN);
			break;
		case LLCP_PTYPE_SYMM:
		case LLCP_PTYPE_DISC:
		case LLCP_PTYPE_RR:
		case LLCP_PTYPE_RNR:
			/* No payload. */
			/* These PDUs shall NOT contain any payload. */
			/* TODO(mikey): flag error? */
			break;
		default:
			/* Unknown/unhandled. */
			break;
	}
	return 0;
}

static int llcp_dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	proto_item *ti;
	proto_tree *llcp_tree;
	guint offset;
	tvbuff_t *next_tvb;
	guint8 dsap;
	guint8 ptype;
	guint8 ssap;

	dsap = tvb_get_bits8(tvb, 0, 6);
	ptype = tvb_get_bits8(tvb, 6, 4);
	ssap = tvb_get_bits8(tvb, 10, 6);

	offset = 0;

	/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_llcp, tvb, 0, -1, ENC_NA);
	llcp_tree = proto_item_add_subtree(ti, ett_llcp);

	proto_tree_add_item(llcp_tree, hf_llcp_dsap, tvb, 0, 2,
			ENC_BIG_ENDIAN);
	proto_tree_add_item(llcp_tree, hf_llcp_ptype, tvb, 0, 2,
			ENC_BIG_ENDIAN);
	proto_tree_add_item(llcp_tree, hf_llcp_ssap, tvb, 0, 2,
			ENC_BIG_ENDIAN);
	offset = 2;

	/* Extract sequence number where appropriate. */
	switch (ptype) {
		case LLCP_PTYPE_I:
		case LLCP_PTYPE_RR:
		case LLCP_PTYPE_RNR:
			proto_tree_add_item(llcp_tree, hf_llcp_seqn, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		default:
			break;
	}

	/* Process information field. */
	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if (tvb_length(next_tvb) > 0) {
		proto_item *sub_tree;
		proto_tree *info_tree;

		sub_tree = proto_tree_add_item(llcp_tree, hf_llcp_info, next_tvb, 0, -1, ENC_NA);
		info_tree = proto_item_add_subtree(sub_tree, ett_llcp_info);

		offset += llcp_dissect_info(next_tvb, pinfo, info_tree, ptype);
	}
	return offset;
}

static int dissect_llcpip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        tvbuff_t *next_tvb;
        int offset;
        int totallen = tvb_length(tvb);

        if (tvb_length(tvb) < 2) {
                return 0;
        }

        pinfo->pseudo_header->llcp.adapter = tvb_get_guint8(tvb, 0);
        pinfo->pseudo_header->llcp.flags = tvb_get_guint8(tvb, 1);
        offset = 2;

        do {
                int amt;
                next_tvb = tvb_new_subset_remaining(tvb, offset);
                amt = dissect_llcp(next_tvb, pinfo, tree);
                if (amt <= 0) {
                        break;
                }
                offset += amt;
        } while (offset < totallen);

        return offset;
}

static int dissect_llcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 dsap;
	guint8 ptype;
	guint8 ssap;

	/* Check that there's enough data */
	if (tvb_length(tvb) < LLCP_HEADER_MIN_LENGTH) {
		return 0;
	}

	#if 0
	version = tvb_get_guint8(tvb, 0);
	request_type = tvb_get_guint8(tvb, 1);
	length = tvb_get_ntohl(tvb, 2);

	if (version != LLCP_VERSION) {
		return 0;
	}
	#endif

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLCP");

	dsap = tvb_get_bits8(tvb, 0, 6);
	ptype = tvb_get_bits8(tvb, 6, 4);
	ssap = tvb_get_bits8(tvb, 10, 6);

	col_set_str(pinfo->cinfo, COL_INFO, val_to_str(ptype, llcp_ptype_vs, "Unknown"));

	/* Set source and dest fields. */
	llcp_set_address(pinfo, ssap, dsap);

	switch (ptype) {
		case LLCP_PTYPE_SYMM:
			break;
		case LLCP_PTYPE_CONNECT:
			conversation_new(pinfo->fd->num, &pinfo->src,
					&pinfo->dst, pinfo->ptype, pinfo->srcport,
					pinfo->destport, NO_ADDR2 );
			break;
		default:
			find_or_create_conversation(pinfo);
			break;
	}

	if (tree) {
		return 2 + llcp_dissect_frame(tvb, pinfo, tree);
	} else {
                return tvb_length(tvb);
        }
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_llcp(void)
{
	module_t *llcp_module;
	module_t *llcpip_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_llcp_dsap,
			{ "DSAP", "llcp.dsap",
				FT_UINT16, BASE_HEX, NULL, 0xfc00,
				"Destination service access point address field", HFILL }
		},
		{ &hf_llcp_ptype,
			{ "Type", "llcp.type",
				FT_UINT16, BASE_DEC, VALS(llcp_ptype_vs), 0x03c0,
				"Payload data unit (PDU) type field", HFILL }
		},
		{ &hf_llcp_ssap,
			{ "SSAP", "llcp.ssap",
				FT_UINT16, BASE_HEX, NULL, 0x003f,
				"Source service access point address field", HFILL }
		},
		{ &hf_llcp_seqn,
			{ "Seqn", "llcp.seqn",
				FT_UINT8, BASE_HEX, NULL, 0xff,
				"Sequence field", HFILL }
		},
		{ &hf_llcp_info,
			{ "Info", "llcp.info",
				FT_BYTES, BASE_NONE, NULL, 0,
				"Message body", HFILL }
		},
		{ &hf_llcp_info_params,
			{ "Parameters", "llcp.param",
				FT_BYTES, BASE_NONE, NULL, 0,
				"Parameter list", HFILL }
		},
		{ &hf_llcp_info_param[LLCP_PARAM_VERSION],
			{ "VERSION", "llcp.param.version",
				FT_UINT8, BASE_CUSTOM, llcp_version_str, 0,
				"Version", HFILL }
		},
		{ &hf_llcp_info_param[LLCP_PARAM_MIUX],
			{ "MIUX", "llcp.param.miux",
				FT_UINT16, BASE_DEC, NULL, 0x0fff,
				"Maximum Information Unit Extension", HFILL }
		},
		{ &hf_llcp_info_param[LLCP_PARAM_WKS],
			{ "WKS", "llcp.param.wks",
				FT_UINT16, BASE_DEC, NULL, 0x00ffffff,
				"Well-Known Service List", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_1],
			{ "SAP1", "llcp.param.wks.1",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_1,
				"SAP1", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_2],
			{ "SAP2", "llcp.param.wks.2",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_2,
				"SAP2", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_3],
			{ "SAP3", "llcp.param.wks.3",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_3,
				"SAP3", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_4],
			{ "SAP4", "llcp.param.wks.4",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_4,
				"SAP4", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_5],
			{ "SAP5", "llcp.param.wks.5",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_5,
				"SAP5", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_6],
			{ "SAP6", "llcp.param.wks.6",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_6,
				"SAP6", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_7],
			{ "SAP7", "llcp.param.wks.7",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_7,
				"SAP7", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_8],
			{ "SAP8", "llcp.param.wks.8",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_8,
				"SAP8", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_9],
			{ "SAP9", "llcp.param.wks.9",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_9,
				"SAP9", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_10],
			{ "SAP10", "llcp.param.wks.10",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_10,
				"SAP10", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_11],
			{ "SAP11", "llcp.param.wks.11",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_11,
				"SAP11", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_12],
			{ "SAP12", "llcp.param.wks.12",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_12,
				"SAP12", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_13],
			{ "SAP13", "llcp.param.wks.13",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_13,
				"SAP13", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_14],
			{ "SAP14", "llcp.param.wks.14",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_14,
				"SAP14", HFILL }
		},
		{ &hf_llcp_info_param_wks[LLCP_WKS_15],
			{ "SAP15", "llcp.param.wks.15",
				FT_UINT16, BASE_HEX, NULL, 1 << LLCP_WKS_15,
				"SAP15", HFILL }
		},
		{ &hf_llcp_info_param[LLCP_PARAM_LTO],
			{ "LTO", "llcp.param.rw",
				FT_UINT8, BASE_DEC, NULL, 0xff,
				"Link Timeout", HFILL }
		},
		{ &hf_llcp_info_param[LLCP_PARAM_RW],
			{ "RW", "llcp.param.rw",
				FT_UINT8, BASE_DEC, NULL, 0x0f,
				"Receive Window", HFILL }
		},
		{ &hf_llcp_info_param[LLCP_PARAM_OPT],
			{ "OPT", "llcp.param.opt",
				FT_UINT8, BASE_HEX, NULL, 0x03,
				"Options", HFILL }
		},
		{ &hf_llcp_frmr_w,
			{ "W", "llcp.frmr.w",
				FT_BOOLEAN, BASE_HEX, NULL, 0x80,
				"Well-formedness Error", HFILL }
		},
		{ &hf_llcp_frmr_i,
			{ "I", "llcp.frmr.i",
				FT_BOOLEAN, BASE_HEX, NULL, 0x40,
				"Information Field Error", HFILL }
		},
		{ &hf_llcp_frmr_r,
			{ "R", "llcp.frmr.r",
				FT_BOOLEAN, BASE_HEX, NULL, 0x20,
				"Receive Sequence Error", HFILL }
		},
		{ &hf_llcp_frmr_s,
			{ "S", "llcp.frmr.s",
				FT_BOOLEAN, BASE_HEX, NULL, 0x10,
				"Send Sequence Error", HFILL }
		},
		{ &hf_llcp_frmr_ptype,
			{ "Ptype", "llcp.frmr.ptype",
				FT_UINT8, BASE_DEC, VALS(llcp_parameter_vs), 0x0f,
				"Type of rejected PDU", HFILL }
		},
		{ &hf_llcp_frmr_seqn,
			{ "Sequence", "llcp.frmr.seqn",
				FT_UINT8, BASE_DEC, NULL, 0xff,
				"Sequence field of rejected PDU (if applicable)", HFILL }
		},
		{ &hf_llcp_frmr_vs,
			{ "VS", "llcp.frmr.vs",
				FT_UINT16, BASE_DEC, NULL, 0xf000,
				"Send state variable", HFILL }
		},
		{ &hf_llcp_frmr_vr,
			{ "VR", "llcp.frmr.vr",
				FT_UINT16, BASE_DEC, NULL, 0x0f00,
				"Receive state variable", HFILL }
		},
		{ &hf_llcp_frmr_vsa,
			{ "VSA", "llcp.frmr.vsa",
				FT_UINT16, BASE_DEC, NULL, 0x00f0,
				"Acknowledgement send state variable", HFILL }
		},
		{ &hf_llcp_frmr_vra,
			{ "VRA", "llcp.frmr.vra",
				FT_UINT16, BASE_DEC, NULL, 0x000f,
				"Acknowledgement receive state variable", HFILL }
		},
		{ &hf_llcp_info_subframes,
			{ "Subframes", "llcp.subframes",
				FT_BYTES, BASE_NONE, NULL, 0,
				"Aggregated subframes", HFILL }
		},
		{ &hf_llcp_reason,
			{ "Reason", "llcp.reason",
				FT_UINT8, BASE_HEX, VALS(llcp_dm_reason_vs), 0,
				"Reason field", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_llcp,
		&ett_llcp_info,
		&ett_llcp_info_params,
		&ett_llcp_info_subframes
	};

	/* Register the protocol name and description */
	proto_llcp = proto_register_protocol("Logical Link Control Protocol", "LLCP", "llcp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_llcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	subdissector_table = register_dissector_table("llcp.sap",
		"LLCP service access point", FT_UINT8, BASE_DEC);
	register_heur_dissector_list("llcp", &heur_subdissector_list);

	/* Register preferences module (See Section 2.6 for more on preferences) */
	llcp_module = prefs_register_protocol(proto_llcp, NULL);

	proto_llcpip = proto_register_protocol("Logical Link Control Protocol in IP", "LLCP-in-IP", "llcpip");
	llcpip_module = prefs_register_protocol(proto_llcpip, NULL);
}
void
proto_reg_handoff_llcp(void)
{
	static gboolean inited = FALSE;
	static dissector_handle_t llcp_handle;
	static dissector_handle_t llcpip_handle;
	static guint llcp_udp_port;
	static guint llcp_tcp_port;

	if (!inited) {
		llcp_handle = new_create_dissector_handle(dissect_llcp, proto_llcp);
		dissector_add_uint("wtap_encap", WTAP_ENCAP_NFC_LLCP, llcp_handle);
		llcpip_handle = new_create_dissector_handle(dissect_llcpip, proto_llcpip);
		inited = TRUE;
	} else {
		dissector_delete_uint("udp.port", llcp_udp_port, llcpip_handle);
		dissector_delete_uint("tcp.port", llcp_tcp_port, llcpip_handle);
	}

	dissector_add_uint("udp.port", global_llcp_udp_port, llcpip_handle);
	llcp_udp_port = global_llcp_udp_port;
	dissector_add_uint("tcp.port", global_llcp_tcp_port, llcpip_handle);
	llcp_tcp_port = global_llcp_tcp_port;
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
