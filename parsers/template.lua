-- Step 1 - Create parser
local luatest = nw.createParser("lua_test", "TEST PARSER")

--[[
This is a test parser.  It is intended to help learn how to write parsers with Lua.

This parser requires a custom meta key.

Concentrator: index-concentrator-custom.xml
 	<key description="Test Alert" level="IndexValues" name="test.alert" valueMax="1000" format="Text"/>
 	
 	
--]]

-- Step 2 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with
luatest:setKeys({
	nwlanguagekey.create("test.alert", nwtypes.Text),
})

-- Step 4 - Do SOMETHING once your token matched
function luatest:tokenFIND(token, first, last)
	nw.createMeta(self.keys["test.alert"], "i_found_you")
end

function luatest:tokenGlover(token, first, last)
	nw.createMeta(self.keys["test.alert"], "i_found_you_glover")
end

-- Step 3 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
luatest:setCallbacks({
	["cnn.com\013\010"] = luatest.tokenFIND,
	["dave glover"] = luatest.tokenGlover,
})





















