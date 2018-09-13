#include "config.h"
#include <stdio.h>
#include <epan/dissectors/packet-usb.h>
#include <epan/reassemble.h>
#include <epan/address_types.h>
#include <epan/proto_data.h>
#include "usbll.h"


#define SPLIT_CONTROL     0b00
#define SPLIT_ISOCHRONOUS 0b01
#define SPLIT_BULK        0b10
#define SPLIT_INTERRUPT   0b11

static int proto_usbll = -1;
static int hf_usbll_pid = -1;
static int hf_usbll_flags = -1;
static int ett_usbll = -1;
static int hf_usbll_device = -1;
static int hf_usbll_endpoint_number = -1;
static int hf_usbll_frame_no = -1;
static int hf_usbll_crc5 = -1;
static int hf_usbll_data = -1;
static int hf_usbll_crc16 = -1;
static int hf_usbll_hub_addr = -1;
static int hf_usbll_sc_bit = -1;
static int hf_usbll_hub_port = -1;
static int hf_usbll_s_bit = -1;
static int hf_usbll_ep_type = -1;
static int hf_usbll_se_bits = -1;

static int usbll_address_type = -1;

static dissector_handle_t usb_handle;

static const value_string pidnames[] = {
    { PID_SOF, "SOF" },
    { PID_DATA0, "DATA0" },
    { PID_DATA1, "DATA1" },
    { PID_DATA2, "DATA2" },
    { PID_MDATA, "MDATA" },
    { PID_OUT, "OUT" },
    { PID_IN, "IN" },
    { PID_SETUP, "SETUP" },
    { PID_ACK, "ACK" },
    { PID_NAK, "NAK" },
    { PID_STALL, "STALL" },
    { PID_NYET, "NYET" },
    { PID_PRE_ERR, "PRE-ERR" },
    { PID_SPLIT, "SPLIT" },
    { PID_PING, "PING" },
    { 0, NULL }
};

static const value_string transactions[] = {
    { IN, "IN" },
    { OUT, "OUT" },
    { SETUP, "SETUP" },
    { PING, "PING" },
    { SPLIT, "SPLIT" },
    { NONE, "NONE" },
    { 0, NULL }
};

static const value_string split_sc_bit[] = {
    { 0, "Start" },
    { 1, "Complete"},
    { 0, NULL}
};

static const value_string split_s_bit[] = {
    { 0, "Full Speed" },
    { 1, "Low Speed"},
    { 0, NULL}
};

static const value_string split_ep_type[] = {
    { SPLIT_CONTROL, "Control" },
    { SPLIT_ISOCHRONOUS, "Isochronous" },
    { SPLIT_BULK, "Bulk" },
    { SPLIT_INTERRUPT, "Interrupt" },
    { 0, "NULL" }
};

static const value_string split_se_bits[] = {
    { 0b00, "HS data is middle of FS data payload" },
    { 0b01, "HS data is end of FS data payload" },
    { 0b10, "HS data is start of FS data payload" },
    { 0b11, "HS data is all of FS data payload" },
    { 0, "NULL" }
};



static usbll_data_t *usbll_data_ptr;

static int usbll_addr_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    const usbll_address_t *addrp = (const usbll_address_t *)addr->data;

    if (addrp->device == 0xff) {
        g_strlcpy(buf, "host", buf_len);
    } else {
        g_snprintf(buf, buf_len, "%d.%d", addrp->device,
                   addrp->endpoint);
    }

    return (int)(strlen(buf)+1);
}

static int usbll_addr_str_len(const address* addr _U_)
{
    return sizeof(usbll_address_t);
}

static const int *usbll_fields[] = {
    NULL
};


/**
 * This function gets called only once per any token, as only in tokens, address
 * is explitly written. Other packets get their address from the context
 */
static usbll_address_t
dissect_usbll_address(tvbuff_t *tvb)
{
    usbll_address_t usbll_address;
    usbll_address.device = tvb_get_guint8(tvb, 3) & 0x7F;
    usbll_address.endpoint = (tvb_get_guint8(tvb, 4) & 0x7) << 1 |
                              tvb_get_guint8(tvb, 3) >> 7;

    return usbll_address;
}

static usbll_direction_t
get_direction(guint8 packet_type, const usbll_data_t *transaction)
{
    if (TOKEN_PACKET(packet_type) || packet_type == PID_SPLIT)
        return HOST_TO_DEVICE;

    if ((HANDSHAKE_PACKET(packet_type)) && transaction->split)
        return DEVICE_TO_HOST;

    if (DATA_PACKET(packet_type)) {
        if (transaction->type == OUT || transaction->type == SETUP)
            return HOST_TO_DEVICE;
        else
            return DEVICE_TO_HOST;
    }

    if (packet_type == PID_ACK) {
        if (transaction->type == IN)
            return HOST_TO_DEVICE;
        else
            return DEVICE_TO_HOST;
    } else {
        return DEVICE_TO_HOST;
    }
}

static void
dissect_usbll_handshake(packet_info *pinfo, guint packet_type)
{
    /* TODO HANDLE NYET */
    if (packet_type == PID_NAK) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Device not ready");
    } else if (packet_type == PID_STALL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Device halted");
    } else if (packet_type == PID_ACK) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Transaction acknowledged");
    } else if (packet_type == PID_NYET) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " No response yet");
    } else if (packet_type == PID_PRE_ERR) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Error on Low / Full speed");
    }
}

/**
 * This function should called only once, on the first dissector
 * call. It updates the protocol's state according to data_ptr
 * saved from the dissector call on the previous frame and a current
 * frame. Returns new data ptr.
 */
static usbll_data_t*
usbll_update_data(tvbuff_t *tvb, packet_info *pinfo, guint8 packet_type, const usbll_data_t *old_data_ptr)
{
    /* allocate a data structure, as it is the first call on this frame */
    usbll_data_t *n_data_ptr = wmem_new0(wmem_file_scope(), usbll_data_t);

    /* attach n_data_ptr to frame number */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_usbll, pinfo->num, n_data_ptr);

    /* update address and transaction type */
    if (TOKEN_PACKET(packet_type)) {
        n_data_ptr->address = dissect_usbll_address(tvb);

        if (old_data_ptr && old_data_ptr->type == SPLIT)
            n_data_ptr->split = TRUE;
        else
            n_data_ptr->split = FALSE;

        if (packet_type == PID_IN)
            n_data_ptr->type = IN;
        else if (packet_type == PID_OUT)
            n_data_ptr->type = OUT;
        else if (packet_type == PID_SETUP)
            n_data_ptr->type = SETUP;
        else if (packet_type == PID_PING)
            n_data_ptr->type = PING;
        else
            n_data_ptr->type = old_data_ptr->type;
    } else if (packet_type == PID_SPLIT) {
        n_data_ptr->address.device = tvb_get_guint8(tvb, 3) & 0x7F;
        n_data_ptr->address.endpoint = tvb_get_guint8(tvb, 4) & 0x7F;
        n_data_ptr->type = SPLIT;
        n_data_ptr->split = TRUE;
    } else {
        if (old_data_ptr) {
            *n_data_ptr = *old_data_ptr;
        } else {
            n_data_ptr->address.device = 0;
            n_data_ptr->address.endpoint = 0;
            n_data_ptr->split = FALSE;
            n_data_ptr->type = NONE;
        }
    }

    /* update packet direction */
    n_data_ptr->packet_direction = get_direction(packet_type, old_data_ptr);

    return n_data_ptr;
}

static usbll_data_t*
usbll_restore_data(packet_info *pinfo)
{
    return (usbll_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_usbll, pinfo->num);
}

static void
set_usbll_address(packet_info *pinfo, usbll_direction_t direction)
{
    usbll_address_t *src_addr, *dst_addr;
    src_addr = wmem_new0(wmem_file_scope(), usbll_address_t);
    dst_addr = wmem_new0(wmem_file_scope(), usbll_address_t);

    if (direction == HOST_TO_DEVICE) {
        src_addr->device = 0xFF;
        src_addr->endpoint = 0;
        dst_addr->device = usbll_data_ptr->address.device;
        dst_addr->endpoint = usbll_data_ptr->address.endpoint;
    } else {
        dst_addr->device = 0xFF;
        dst_addr->endpoint = 0;
        src_addr->device = usbll_data_ptr->address.device;
        src_addr->endpoint = usbll_data_ptr->address.endpoint;
    }

    pinfo->ptype = PT_NONE;
    pinfo->srcport = src_addr->endpoint;
    pinfo->destport = dst_addr->endpoint;
    set_address(&pinfo->net_src, usbll_address_type, sizeof(usbll_address_t), (char *)src_addr);
    copy_address_shallow(&pinfo->src, &pinfo->net_src);

    set_address(&pinfo->net_dst, usbll_address_type, sizeof(usbll_address_t), (char *)dst_addr);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
}

static void
dissect_usbll_token(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree, proto_item *subtree, usbll_data_t *data_ptr)
{
    /**
     * Show endpoint address in a protocol info column and protocol
     * header
     */
	col_append_fstr(pinfo->cinfo, COL_INFO, " Endpoint address: %d.%d",
                    data_ptr->address.device, data_ptr->address.endpoint);
    proto_item_append_text(tree, ", Endpoint address: %d.%d",
                           usbll_data_ptr->address.device, usbll_data_ptr->address.endpoint);

    /* Show 'device', 'endpoint' and 'crc5' fields in a protocol subtree */
    proto_tree_add_bitmask(subtree, tvb, 3, hf_usbll_device, ett_usbll,
                           usbll_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(subtree, tvb, 3, hf_usbll_endpoint_number, ett_usbll,
                           usbll_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(subtree, tvb, 4, hf_usbll_crc5, ett_usbll,
                           usbll_fields, ENC_LITTLE_ENDIAN);
}

static void
dissect_usbll_data(packet_info *pinfo, tvbuff_t *tvb, proto_item *tree, proto_item *subtree, guint offset)
{
    proto_tree_add_item(subtree, hf_usbll_data, tvb, offset, tvb_captured_length_remaining(tvb, offset) - 2, ENC_LITTLE_ENDIAN);

     /* Last 2 bytes are occupied by the CRC16 of the data packet */
    proto_tree_add_item(subtree, hf_usbll_crc16, tvb, tvb_captured_length(tvb) - 2, 2, ENC_LITTLE_ENDIAN);

    tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);

     /* Cut off last 2 bytes occupied by CRC16 */
    tvb_set_reported_length(next_tvb, tvb_reported_length(next_tvb) - 2);
    if (usb_handle != 0)
          call_dissector_only(usb_handle, next_tvb, pinfo, tree, usbll_data_ptr);
}

static void
dissect_usbll_sof(packet_info *pinfo, tvbuff_t *tvb, proto_item *tree, proto_item *subtree)
{
    guint16 frame_no = tvb_get_guint16(tvb, 3, ENC_LITTLE_ENDIAN) & 0x7FF;
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Frame number: %d",
                 frame_no);
    proto_item_append_text(tree, " Frame number: %d", frame_no);
    proto_tree_add_bitmask(subtree, tvb, 3, hf_usbll_frame_no, ett_usbll,
                           usbll_fields, ENC_LITTLE_ENDIAN);

    proto_tree_add_bitmask(subtree, tvb, 4, hf_usbll_crc5, ett_usbll,
                           usbll_fields, ENC_LITTLE_ENDIAN);
}

static void
dissect_usbll_split(packet_info *pinfo, tvbuff_t *tvb, proto_item *tree)
{
    guint offset = 3;

    proto_tree_add_bitmask(tree, tvb, offset, hf_usbll_hub_addr, ett_usbll, usbll_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset, hf_usbll_sc_bit, ett_usbll, usbll_fields, ENC_LITTLE_ENDIAN);

    guint8 sc = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sc, split_sc_bit, "Unknown (0x%02x)"));

    offset += 1;

    proto_tree_add_bitmask(tree, tvb, offset, hf_usbll_hub_port, ett_usbll, usbll_fields, ENC_LITTLE_ENDIAN);
    guint8 ep_type = tvb_get_guint8(tvb, offset + 1) & 0x06;

    if (ep_type == SPLIT_ISOCHRONOUS) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_usbll_se_bits, ett_usbll, usbll_fields, ENC_LITTLE_ENDIAN);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_usbll_s_bit, ett_usbll, usbll_fields, ENC_LITTLE_ENDIAN);
    }
    offset += 1;

    proto_tree_add_bitmask(tree, tvb, offset, hf_usbll_ep_type, ett_usbll, usbll_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, offset, hf_usbll_crc5, ett_usbll, usbll_fields, ENC_LITTLE_ENDIAN);

}

static int
dissect_usbll(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    proto_item *usbll_tree = NULL;
    proto_item *usbll_subtree = NULL;
    guint8 packet_type = tvb_get_guint8(tvb, 2);


    /* set 'protocol' column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBLL");

    /* print packet type in 'info' column */
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(packet_type, pidnames, "Unknown (0x%02x)"));

    /* Add a new protocol 'header' */
    usbll_tree = proto_tree_add_item(tree, proto_usbll, tvb, 0, -1, ENC_NA);
    proto_item_append_text(usbll_tree, ", Type %s", val_to_str(packet_type, pidnames, "Unknown (0x%02x)"));

    /**
     *  add a subtree, which is going to be filled with fields' value,
     *  initially flags and pid, which are common for all packets
     */
    usbll_subtree = proto_item_add_subtree(usbll_tree, ett_usbll);

    proto_tree_add_item(usbll_subtree, hf_usbll_flags, tvb, 0, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(usbll_subtree, hf_usbll_pid, tvb, 2, 1, ENC_LITTLE_ENDIAN);

    if (SOF_PACKET(packet_type)) {
        dissect_usbll_sof(pinfo, tvb, usbll_tree, usbll_subtree);

        return tvb_captured_length(tvb);
    }

    /**
     *  If the packet has been already dissected its data is saved and can be
     *  restored based on the frame number. Otherwise, new data should be computed
     *  based on the previous packet's data
     */
    if (PINFO_FD_VISITED(pinfo))
        usbll_data_ptr = usbll_restore_data(pinfo);
    else
        usbll_data_ptr = usbll_update_data(tvb, pinfo, packet_type, usbll_data_ptr);

    set_usbll_address(pinfo, usbll_data_ptr->packet_direction);
    proto_item_append_text(usbll_tree, ", Transaction: %s", val_to_str(usbll_data_ptr->type, transactions, "Unkown (0x%02x)"));

    if (TOKEN_PACKET(packet_type)) {
        dissect_usbll_token(tvb, pinfo, usbll_tree, usbll_subtree, usbll_data_ptr);
    } else if (HANDSHAKE_PACKET(packet_type)) {
        dissect_usbll_handshake(pinfo, packet_type);
    } else if (DATA_PACKET(packet_type)) {
        dissect_usbll_data(pinfo, tvb, tree, usbll_subtree, 3);
    } else if (packet_type == PID_SPLIT) {
        dissect_usbll_split(pinfo, tvb, usbll_subtree);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_usbll(void)
{
    proto_usbll = proto_register_protocol (
        "USB Link Layer",
        "USBLL",
        "usbll"
    );

    /* register arrays */
    static hf_register_info hf[] = {
        { &hf_usbll_flags,
            { "Flags", "usbll.flags",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbll_pid,
            { "Packet Identifier", "usbll.pid",
            FT_UINT8, BASE_DEC,
            VALS(pidnames), 0x0,
            NULL, HFILL }
        },
        { &hf_usbll_device,
            { "Device", "usbll.device",
            FT_UINT8, BASE_DEC, NULL, 0x7F,
            "USB device address", HFILL}
        },
        { &hf_usbll_endpoint_number,
            { "Endpoint", "usbll.endpoint",
            FT_UINT16, BASE_DEC, NULL, 0x780,
            "USB endpoint address", HFILL}
        },
        { &hf_usbll_crc5,
            { "CRC5", "usbll.crc5",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            "CRC5 code", HFILL}
        },
        { &hf_usbll_frame_no,
            { "Frame no", "usbll.frame_no",
            FT_UINT16, BASE_DEC, NULL, 0x7FF,
            "USB frame number", HFILL}
        },
        { &hf_usbll_data,
            { "Data", "usbll.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            "USB DATA", HFILL}
        },
        { &hf_usbll_crc16,
            { "CRC16", "usbll.crc16",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            "USBLL CRC16", HFILL }
        },
        { &hf_usbll_hub_addr,
            { "Hub Address", "usbll.hub_addr",
            FT_UINT8, BASE_DEC, NULL, 0x7F,
            "USBLL Hub Address", HFILL}
        },
        { &hf_usbll_sc_bit,
            { "Start / Complete", "usbll.sc",
            FT_UINT8, BASE_DEC, VALS(split_sc_bit), 0x80,
            "USBLL Start / Complete", HFILL}
        },
        { &hf_usbll_hub_port,
            { "Hub Port", "usbll.hub_port",
            FT_UINT8, BASE_DEC, NULL, 0x7F,
            "USBLL Hub Port", HFILL}
        },
        { &hf_usbll_s_bit,
            { "Speed", "usbll.speed",
            FT_UINT8, BASE_DEC, VALS(split_s_bit), 0x80,
            "USBLL Speed", HFILL}
        },
        { &hf_usbll_ep_type,
            { "Endpoint type", "usbll.endpoint_type",
            FT_UINT8, BASE_DEC, VALS(split_ep_type), 0x06,
            "USBLL Endpoint Type", HFILL}
        },
        { &hf_usbll_se_bits,
            { "Start and End", "usbll.start_end",
            FT_UINT16, BASE_DEC, VALS(split_se_bits), 0x0180,
            "USBLL Start and End", HFILL}
        },
    };

    static gint *ett[] = {
        &ett_usbll
    };


    proto_register_field_array(proto_usbll, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    usbll_address_type = address_type_dissector_register("AT_USBLL", "USBLL Address",
                                                          usbll_addr_to_str, usbll_addr_str_len,
                                                          NULL, NULL, NULL, NULL, NULL);
}

void
proto_reg_handoff_usbll(void)
{
    static dissector_handle_t usbll_handle;

    usb_handle = find_dissector("usb");

    usbll_handle = create_dissector_handle(dissect_usbll, proto_usbll);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER0, usbll_handle);
}
