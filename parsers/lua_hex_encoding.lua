-- Step 1 - Create parser
local lua_hex_encoding = nw.createParser("possible_hex_encoding", "Possible Hex Encoding")
--[[
This is a test parser.  It is intended to help learn how to write parsers with Lua.
This parser requires a custom meta key.
Concentrator: index-concentrator-custom.xml
    <key description="Test Alert" level="IndexValues" name="test.alert" valueMax="1000" format="Text"/>
    
    
--]]
-- Step 2 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with
lua_hex_encoding:setKeys({
    nwlanguagekey.create("ioc", nwtypes.Text),
})
-- Step 4 - Do SOMETHING once your token matched

function lua_hex_encoding:sessionBegin()
	-- reset parser_state for the new session
	hexval = {}
end

function lua_hex_encoding:tokenFIND(token, first, last)
   if #hexval <= 10 then
        table.insert(hexval, token)
    end
    -- if we have our tokens in the table, then lets call it what it is
    if #hexval == 10 then
        -- register meta
        --nw.logInfo("*** POSSIBLE_\X_ENCODING ***")
        nw.createMeta(self.keys["ioc"], "possible_hex_encoding")      
    end
end

-- Step 3 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
lua_hex_encoding:setCallbacks({
	[nwevents.OnSessionBegin] = lua_hex_encoding.sessionBegin,
    ["\\x00"] = lua_hex_encoding.tokenFIND,
	["\\x01"] = lua_hex_encoding.tokenFIND,
	["\\x02"] = lua_hex_encoding.tokenFIND,
	["\\x03"] = lua_hex_encoding.tokenFIND,
	["\\x04"] = lua_hex_encoding.tokenFIND,
	["\\x05"] = lua_hex_encoding.tokenFIND,
	["\\x06"] = lua_hex_encoding.tokenFIND,
	["\\x07"] = lua_hex_encoding.tokenFIND,
	["\\x08"] = lua_hex_encoding.tokenFIND,
	["\\x09"] = lua_hex_encoding.tokenFIND,
	["\\x10"] = lua_hex_encoding.tokenFIND,
	["\\x11"] = lua_hex_encoding.tokenFIND,
	["\\x12"] = lua_hex_encoding.tokenFIND,
	["\\x13"] = lua_hex_encoding.tokenFIND,
	["\\x14"] = lua_hex_encoding.tokenFIND,
	["\\x15"] = lua_hex_encoding.tokenFIND,
	["\\x16"] = lua_hex_encoding.tokenFIND,
	["\\x17"] = lua_hex_encoding.tokenFIND,
	["\\x18"] = lua_hex_encoding.tokenFIND,
	["\\x19"] = lua_hex_encoding.tokenFIND,
	["\\x20"] = lua_hex_encoding.tokenFIND,
	["\\x21"] = lua_hex_encoding.tokenFIND,
	["\\x22"] = lua_hex_encoding.tokenFIND,
	["\\x23"] = lua_hex_encoding.tokenFIND,
	["\\x24"] = lua_hex_encoding.tokenFIND,
	["\\x25"] = lua_hex_encoding.tokenFIND,
	["\\x26"] = lua_hex_encoding.tokenFIND,
	["\\x27"] = lua_hex_encoding.tokenFIND,
	["\\x28"] = lua_hex_encoding.tokenFIND,
	["\\x29"] = lua_hex_encoding.tokenFIND,
	["\\x30"] = lua_hex_encoding.tokenFIND,
	["\\x31"] = lua_hex_encoding.tokenFIND,
	["\\x32"] = lua_hex_encoding.tokenFIND,
	["\\x33"] = lua_hex_encoding.tokenFIND,
	["\\x34"] = lua_hex_encoding.tokenFIND,
	["\\x35"] = lua_hex_encoding.tokenFIND,
	["\\x36"] = lua_hex_encoding.tokenFIND,
	["\\x37"] = lua_hex_encoding.tokenFIND,
	["\\x38"] = lua_hex_encoding.tokenFIND,
	["\\x39"] = lua_hex_encoding.tokenFIND,
	["\\x40"] = lua_hex_encoding.tokenFIND,
	["\\x41"] = lua_hex_encoding.tokenFIND,
	["\\x42"] = lua_hex_encoding.tokenFIND,
	["\\x43"] = lua_hex_encoding.tokenFIND,
	["\\x44"] = lua_hex_encoding.tokenFIND,
	["\\x45"] = lua_hex_encoding.tokenFIND,
	["\\x46"] = lua_hex_encoding.tokenFIND,
	["\\x47"] = lua_hex_encoding.tokenFIND,
	["\\x48"] = lua_hex_encoding.tokenFIND,
	["\\x49"] = lua_hex_encoding.tokenFIND,
	["\\x50"] = lua_hex_encoding.tokenFIND,
	["\\x51"] = lua_hex_encoding.tokenFIND,
	["\\x52"] = lua_hex_encoding.tokenFIND,
	["\\x53"] = lua_hex_encoding.tokenFIND,
	["\\x54"] = lua_hex_encoding.tokenFIND,
	["\\x55"] = lua_hex_encoding.tokenFIND,
	["\\x56"] = lua_hex_encoding.tokenFIND,
	["\\x57"] = lua_hex_encoding.tokenFIND,
	["\\x58"] = lua_hex_encoding.tokenFIND,
	["\\x59"] = lua_hex_encoding.tokenFIND,
	["\\x60"] = lua_hex_encoding.tokenFIND,
	["\\x61"] = lua_hex_encoding.tokenFIND,
	["\\x62"] = lua_hex_encoding.tokenFIND,
	["\\x63"] = lua_hex_encoding.tokenFIND,
	["\\x64"] = lua_hex_encoding.tokenFIND,
	["\\x65"] = lua_hex_encoding.tokenFIND,
	["\\x66"] = lua_hex_encoding.tokenFIND,
	["\\x67"] = lua_hex_encoding.tokenFIND,
	["\\x68"] = lua_hex_encoding.tokenFIND,
	["\\x69"] = lua_hex_encoding.tokenFIND,
	["\\x70"] = lua_hex_encoding.tokenFIND,
	["\\x71"] = lua_hex_encoding.tokenFIND,
	["\\x72"] = lua_hex_encoding.tokenFIND,
	["\\x73"] = lua_hex_encoding.tokenFIND,
	["\\x74"] = lua_hex_encoding.tokenFIND,
	["\\x75"] = lua_hex_encoding.tokenFIND,
	["\\x76"] = lua_hex_encoding.tokenFIND,
	["\\x77"] = lua_hex_encoding.tokenFIND,
	["\\x78"] = lua_hex_encoding.tokenFIND,
	["\\x79"] = lua_hex_encoding.tokenFIND,
	["\\x80"] = lua_hex_encoding.tokenFIND,
	["\\x81"] = lua_hex_encoding.tokenFIND,
	["\\x82"] = lua_hex_encoding.tokenFIND,
	["\\x83"] = lua_hex_encoding.tokenFIND,
	["\\x84"] = lua_hex_encoding.tokenFIND,
	["\\x85"] = lua_hex_encoding.tokenFIND,
	["\\x86"] = lua_hex_encoding.tokenFIND,
	["\\x87"] = lua_hex_encoding.tokenFIND,
	["\\x88"] = lua_hex_encoding.tokenFIND,
	["\\x89"] = lua_hex_encoding.tokenFIND,
	["\\x90"] = lua_hex_encoding.tokenFIND,
	["\\x91"] = lua_hex_encoding.tokenFIND,
	["\\x92"] = lua_hex_encoding.tokenFIND,
	["\\x93"] = lua_hex_encoding.tokenFIND,
	["\\x94"] = lua_hex_encoding.tokenFIND,
	["\\x95"] = lua_hex_encoding.tokenFIND,
	["\\x96"] = lua_hex_encoding.tokenFIND,
	["\\x97"] = lua_hex_encoding.tokenFIND,
	["\\x98"] = lua_hex_encoding.tokenFIND,
	["\\x99"] = lua_hex_encoding.tokenFIND,
})