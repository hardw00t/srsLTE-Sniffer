--[[
    srsRAN Sniffer Wireshark Dissector

    This Lua dissector handles UDP packets from the srsRAN-Sniffer
    (formerly srsLTE-Sniffer) with custom framing format.

    Compatible with srsRAN_4G (formerly srsLTE) version 23.04+

    Packet Format:
    - Magic number: 4 bytes (0x4C544553 "LTES")
    - SFN: 4 bytes (System Frame Number)
    - SFIDX: 1 byte (Subframe Index)
    - TB_IDX: 1 byte (Transport Block Index)
    - Payload Length: 2 bytes
    - Payload: Variable length

    Installation:
    1. Copy this file to Wireshark plugins directory:
       - Windows: %APPDATA%\Wireshark\plugins\
       - Linux: ~/.local/lib/wireshark/plugins/
       - macOS: ~/.config/wireshark/plugins/
    2. Restart Wireshark or reload Lua plugins (Analyze > Reload Lua Plugins)

    Copyright 2013-2015 Software Radio Systems Limited
    SPDX-License-Identifier: AGPL-3.0-or-later
--]]

-- Protocol definition (keep "srsran" for modern installs, with srsLTE alias)
local srsran_proto = Proto("srsran", "srsRAN Sniffer Protocol")

-- Magic number constant
local MAGIC_NUMBER = 0x4C544553  -- "LTES" in big-endian

-- Protocol fields
local f_magic       = ProtoField.uint32("srsran.magic", "Magic Number", base.HEX)
local f_sfn         = ProtoField.uint32("srsran.sfn", "System Frame Number", base.DEC)
local f_sfidx       = ProtoField.uint8("srsran.sfidx", "Subframe Index", base.DEC)
local f_tb_idx      = ProtoField.uint8("srsran.tb_idx", "Transport Block Index", base.DEC)
local f_payload_len = ProtoField.uint16("srsran.payload_len", "Payload Length", base.DEC)
local f_payload     = ProtoField.bytes("srsran.payload", "Payload")

-- Extended fields for decoded content
local f_data_type = ProtoField.string("srsran.type", "Data Type")
local f_imsi      = ProtoField.string("srsran.imsi", "IMSI")
local f_stmsi     = ProtoField.string("srsran.stmsi", "S-TMSI")
local f_rnti      = ProtoField.uint16("srsran.rnti", "RNTI", base.HEX)
local f_cell_id   = ProtoField.uint32("srsran.cell_id", "Cell ID", base.DEC)

srsran_proto.fields = {
    f_magic, f_sfn, f_sfidx, f_tb_idx, f_payload_len, f_payload,
    f_data_type, f_imsi, f_stmsi, f_rnti, f_cell_id
}

-- Expert info
local ef_invalid_magic = ProtoExpert.new("srsran.invalid_magic", "Invalid magic number",
                                          expert.group.MALFORMED, expert.severity.ERROR)
local ef_truncated = ProtoExpert.new("srsran.truncated", "Truncated packet",
                                      expert.group.MALFORMED, expert.severity.ERROR)

srsran_proto.experts = { ef_invalid_magic, ef_truncated }

-- Helper: Check if payload contains IMSI pattern
-- IMSI format: [9][5][MCC][MNC][MSIN][8]
local function find_imsi(payload_hex)
    local pattern = "9(5%d%d%d%d%d%d%d%d%d%d%d%d%d%d)8"
    local match = payload_hex:match(pattern)
    if match then
        return match
    end
    return nil
end

-- Helper: Check if payload contains S-TMSI
-- S-TMSI: MMEC (1 byte) + M-TMSI (4 bytes) = 10 hex characters
local function find_stmsi(payload_hex)
    -- Look for 10-character hex sequences with at least one hex letter
    for i = 1, #payload_hex - 9 do
        local candidate = payload_hex:sub(i, i + 9)
        if candidate:match("^%x+$") and candidate:match("[a-fA-F]") then
            return candidate
        end
    end
    return nil
end

-- Helper: Detect RRC message type from payload
local function detect_message_type(payload_hex)
    if #payload_hex < 2 then
        return "UNKNOWN"
    end

    -- First byte patterns for different RRC messages
    local first_byte = tonumber(payload_hex:sub(1, 2), 16)
    if first_byte == nil then
        return "UNKNOWN"
    end

    -- Paging patterns
    if first_byte >= 0x40 and first_byte <= 0x6F then
        return "PAGING"
    end

    -- SIB1 patterns (SystemInformationBlockType1)
    if first_byte == 0x68 or first_byte == 0x69 then
        return "SIB1"
    end

    -- SystemInformation (containing SIB2+)
    if first_byte == 0x00 or first_byte == 0x01 then
        return "SI"
    end

    return "DL-CCCH"
end

-- Dissector function
function srsran_proto.dissector(buffer, pinfo, tree)
    -- Minimum header size: 4 + 4 + 1 + 1 + 2 = 12 bytes
    local MIN_HEADER = 12

    if buffer:len() < MIN_HEADER then
        return 0
    end

    -- Check magic number
    local magic = buffer(0, 4):uint()
    if magic ~= MAGIC_NUMBER then
        return 0
    end

    -- Set protocol column
    pinfo.cols.protocol = "srsRAN"

    -- Create protocol tree
    local subtree = tree:add(srsran_proto, buffer(), "srsRAN Sniffer Protocol")

    -- Parse header fields
    subtree:add(f_magic, buffer(0, 4))

    local sfn = buffer(4, 4):uint()
    subtree:add(f_sfn, buffer(4, 4))

    local sfidx = buffer(8, 1):uint()
    subtree:add(f_sfidx, buffer(8, 1))

    local tb_idx = buffer(9, 1):uint()
    subtree:add(f_tb_idx, buffer(9, 1))

    local payload_len = buffer(10, 2):uint()
    subtree:add(f_payload_len, buffer(10, 2))

    -- Check for truncation
    if buffer:len() < MIN_HEADER + payload_len then
        subtree:add_proto_expert_info(ef_truncated)
        pinfo.cols.info = string.format("srsRAN [TRUNCATED] SFN=%d.%d", sfn, sfidx)
        return MIN_HEADER
    end

    -- Add payload
    if payload_len > 0 then
        local payload_tree = subtree:add(f_payload, buffer(MIN_HEADER, payload_len))

        -- Try to decode payload content
        local payload_hex = ""
        for i = 0, payload_len - 1 do
            payload_hex = payload_hex .. string.format("%02x", buffer(MIN_HEADER + i, 1):uint())
        end

        -- Detect data type and extract identities
        local data_type = detect_message_type(payload_hex)
        local imsi = find_imsi(payload_hex)
        local stmsi = find_stmsi(payload_hex)

        if imsi then
            data_type = "PAGING"
            subtree:add(f_data_type, "PAGING (IMSI)")
            subtree:add(f_imsi, imsi)

            if stmsi then
                subtree:add(f_stmsi, stmsi)
            end

            pinfo.cols.info = string.format("Paging IMSI=%s SFN=%d.%d", imsi, sfn, sfidx)
        elseif stmsi then
            data_type = "PAGING"
            subtree:add(f_data_type, "PAGING (S-TMSI)")
            subtree:add(f_stmsi, stmsi)

            pinfo.cols.info = string.format("Paging S-TMSI=%s SFN=%d.%d", stmsi, sfn, sfidx)
        elseif data_type == "SIB1" then
            subtree:add(f_data_type, "SIB1")
            pinfo.cols.info = string.format("SIB1 SFN=%d.%d len=%d", sfn, sfidx, payload_len)
        elseif data_type == "SI" then
            subtree:add(f_data_type, "SI (SIB2+)")
            pinfo.cols.info = string.format("SI SFN=%d.%d len=%d", sfn, sfidx, payload_len)
        else
            subtree:add(f_data_type, data_type)
            pinfo.cols.info = string.format("srsRAN SFN=%d.%d len=%d", sfn, sfidx, payload_len)
        end
    else
        pinfo.cols.info = string.format("srsRAN SFN=%d.%d (empty)", sfn, sfidx)
    end

    return buffer:len()
end

-- Register for UDP port (configurable)
local udp_port = DissectorTable.get("udp.port")
udp_port:add(5000, srsran_proto)  -- Default port
udp_port:add(5001, srsran_proto)
udp_port:add(5002, srsran_proto)

-- Heuristic dissector for any UDP with our magic number
local function heuristic_checker(buffer, pinfo, tree)
    if buffer:len() < 12 then
        return false
    end

    local magic = buffer(0, 4):uint()
    if magic == MAGIC_NUMBER then
        srsran_proto.dissector(buffer, pinfo, tree)
        return true
    end

    return false
end

-- Register heuristic dissector
srsran_proto:register_heuristic("udp", heuristic_checker)

-- Post-dissector for statistics
local srsran_postdissector = Proto("srsran_post", "srsRAN Post-dissector")

function srsran_postdissector.dissector(buffer, pinfo, tree)
    -- This runs after main dissection
    -- Can be used for statistics or additional processing
end

-- Register post-dissector
register_postdissector(srsran_postdissector)

-- Preferences
srsran_proto.prefs.udp_port = Pref.uint("UDP Port", 5000, "UDP port for srsRAN traffic")

function srsran_proto.prefs_changed()
    local new_port = srsran_proto.prefs.udp_port
    -- Update port registration
    udp_port:add(new_port, srsran_proto)
end

-- Print info on load
print("srsRAN Sniffer dissector loaded. Listening on UDP ports 5000-5002.")
print("  Filter: srsran | srsran.imsi | srsran.stmsi")
