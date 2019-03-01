-- Step 1 - Create parser
local luahttprcode = nw.createParser("lua_http_rcode", "LUA HTTP RESPONSE CODES", "80")

--[[
    DESCRIPTION

        Parse all http response codes...just the code numbers not the comment


    VERSION
		
        2015-12-16 - Initial development
        2019-02-27 - Added complete Response code to result.code along with just number
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    META KEYS
    
    	None
    	
   
    NOTES
    
		None
		
	
        
--]]

-- Step 2 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with
luahttprcode:setKeys({
	nwlanguagekey.create("result.code"),
})

-- Step 4 - Do SOMETHING once your token matched
function luahttprcode:tokenRESPONSE(token, first, last)
	-- set position to byte match
	current_position = last + 1
	-- get the payload
	local payload = nw.getPayload(current_position, current_position + 32) -- only getting payload that i need
	-- Find the space after the number and before the comment text (ex. "200 OK")
	local num_temp = payload:find(" ", 1, -1) -- 1 is the first byte, -1 is the last byte
	-- if we found the space
	if num_temp ~= nil then
		-- we don't want to read the space
		num_temp = num_temp - 1
		-- read up to the space
		local string_temp = payload:tostring(1, num_temp)
		-- make sure the read succeeded
		if string_temp ~= nil then
			-- register what was read as meta
			--nw.logInfo("***HTTP RESPONSE CODE: " .. string_temp .. " ***")
			nw.createMeta(self.keys["result.code"], string_temp)
		end
	end
	local num_temp2 = payload:find("\13\10", 1, -1) -- 1 is the first byte, -1 is the last byte
	-- if we found the end
	if num_temp2 ~= nil then
		-- we don't want to read the space
		num_temp2 = num_temp2 - 1
		-- read up to the space
		local string_temp2 = payload:tostring(1, num_temp2)
		-- make sure the read succeeded
		if string_temp2 ~= nil then
			-- register what was read as meta
			--nw.logInfo("***HTTP RESPONSE CODE: " .. string_temp .. " ***")
			nw.createMeta(self.keys["result.code"], string_temp2)
		end
	end
end


-- Step 3 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
luahttprcode:setCallbacks({
	["^HTTP/1.1 "] = luahttprcode.tokenRESPONSE, -- the carat ^ indicates beginning of line
	["^HTTP/1.0 "] = luahttprcode.tokenRESPONSE,
	["^HTTP/0.9 "] = luahttprcode.tokenRESPONSE, 
})
					
