--[[
    srsLTE Sniffer Wireshark Dissector

    This Lua dissector handles UDP packets from the srsLTE-Sniffer
    with custom framing format.

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

-- Protocol definition
local srslte_proto = Proto("srslte", "srsLTE Sniffer Protocol")

-- Magic number constant
local MAGIC_NUMBER = 0x4C544553  -- "LTES" in big-endian

-- Protocol fields
local f_magic     = ProtoField.uint32("srslte.magic", "Magic Number", base.HEX)
local f_sfn       = ProtoField.uint32("srslte.sfn", "System Frame Number", base.DEC)
local f_sfidx     = ProtoField.uint8("srslte.sfidx", "Subframe Index", base.DEC)
local f_tb_idx    = ProtoField.uint8("srslte.tb_idx", "Transport Block Index", base.DEC)
local f_payload_len = ProtoField.uint16("srslte.payload_len", "Payload Length", base.DEC)
local f_payload   = ProtoField.bytes("srslte.payload", "Payload")

-- Extended fields for decoded content
local f_data_type = ProtoField.string("srslte.type", "Data Type")
local f_imsi      = ProtoField.string("srslte.imsi", "IMSI")
local f_stmsi     = ProtoField.string("srslte.stmsi", "S-TMSI")
local f_rnti      = ProtoField.uint16("srslte.rnti", "RNTI", base.HEX)

srslte_proto.fields = {
    f_magic, f_sfn, f_sfidx, f_tb_idx, f_payload_len, f_payload,
    f_data_type, f_imsi, f_stmsi, f_rnti
}

-- Expert info
local ef_invalid_magic = ProtoExpert.new("srslte.invalid_magic", "Invalid magic number",
                                          expert.group.MALFORMED, expert.severity.ERROR)
local ef_truncated = ProtoExpert.new("srslte.truncated", "Truncated packet",
                                      expert.group.MALFORMED, expert.severity.ERROR)

srslte_proto.experts = { ef_invalid_magic, ef_truncated }

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
-- S-TMSI: 10 hex characters containing at least one a-f
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

-- Dissector function
function srslte_proto.dissector(buffer, pinfo, tree)
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
    pinfo.cols.protocol = "srsLTE"

    -- Create protocol tree
    local subtree = tree:add(srslte_proto, buffer(), "srsLTE Sniffer Protocol")

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
        pinfo.cols.info = string.format("srsLTE [TRUNCATED] SFN=%d.%d", sfn, sfidx)
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
        local data_type = "UNKNOWN"
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
        else
            -- Check for SIB patterns
            if payload_hex:sub(1, 2) == "68" or payload_hex:sub(1, 2) == "40" then
                data_type = "SIB"
                subtree:add(f_data_type, "SIB")
                pinfo.cols.info = string.format("SIB SFN=%d.%d len=%d", sfn, sfidx, payload_len)
            else
                subtree:add(f_data_type, data_type)
                pinfo.cols.info = string.format("srsLTE SFN=%d.%d len=%d", sfn, sfidx, payload_len)
            end
        end
    else
        pinfo.cols.info = string.format("srsLTE SFN=%d.%d (empty)", sfn, sfidx)
    end

    return buffer:len()
end

-- Register for UDP port (configurable)
local udp_port = DissectorTable.get("udp.port")
udp_port:add(5000, srslte_proto)  -- Default port
udp_port:add(5001, srslte_proto)
udp_port:add(5002, srslte_proto)

-- Heuristic dissector for any UDP with our magic number
local function heuristic_checker(buffer, pinfo, tree)
    if buffer:len() < 12 then
        return false
    end

    local magic = buffer(0, 4):uint()
    if magic == MAGIC_NUMBER then
        srslte_proto.dissector(buffer, pinfo, tree)
        return true
    end

    return false
end

-- Register heuristic dissector
srslte_proto:register_heuristic("udp", heuristic_checker)

-- Post-dissector to add srsLTE filter
local srslte_postdissector = Proto("srslte_post", "srsLTE Post-dissector")

function srslte_postdissector.dissector(buffer, pinfo, tree)
    -- This runs after main dissection
    -- Can be used for statistics or additional processing
end

-- Register post-dissector
register_postdissector(srslte_postdissector)

-- Preferences
srslte_proto.prefs.udp_port = Pref.uint("UDP Port", 5000, "UDP port for srsLTE traffic")

function srslte_proto.prefs_changed()
    local new_port = srslte_proto.prefs.udp_port
    -- Update port registration
    udp_port:add(new_port, srslte_proto)
end

-- Print info on load
print("srsLTE Sniffer dissector loaded. Listening on UDP ports 5000-5002.")
