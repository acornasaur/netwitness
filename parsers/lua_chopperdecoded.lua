-- Step 1 - Create parser
local lua_chopperdecoded = nw.createParser("lua_chopperdecoded", "Decode Chopper Base64 commands")

--[[
    DESCRIPTION

        Decode Chopper Base64 commands


    VERSION
		
        2018-04-17 - Initial development
       
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
lua_chopperdecoded:setKeys({
	nwlanguagekey.create("command", nwtypes.Text),
})

-- Step 4 - Do SOMETHING once your token matched
function lua_chopperdecoded:sessionBegin()
	-- reset global variables
	mycmd1 = nil
	mycmd2 = nil
end


function lua_chopperdecoded:tokenDECODE(token, first, last)

	current_position = last + 1
	--nw.logInfo("*** TOKEN MATCH ***")
	local payload = nw.getPayload(current_position, current_position + 4096)
	local morez = payload:find("&", z1l, -1)	
	local delim1 = morez
	if delim1 then
		--nw.logInfo("*** Z1 & MATCH ***")
		local cmd1 = payload:tostring(1, delim1 -1)
		if cmd1 then
			--nw.logInfo("*** COMMAND: " .. cmd1 .. " ***")
			local decode1 = nw.base64Decode(cmd1)
			if decode1 then
				--nw.createMeta(self.keys["command"], decode1)
				--nw.logInfo("*** COMMAND1: " .. decode1 .. " ***")
				mycmd1 = decode1
			end
		end
	else
		local delim1 = payload:find("%", z1l, -1)
		if delim1 then
			--nw.logInfo("*** Z1 & MATCH2 ***")
			local cmd1 = payload:tostring(1, delim1 -1)
			if cmd1 then
				--nw.logInfo("*** COMMAND: " .. cmd1 .. " ***")
				local decode1 = nw.base64Decode(cmd1)
				if decode1 then
					--nw.createMeta(self.keys["command"], decode1)
					--nw.logInfo("*** COMMAND1: " .. decode1 .. " ***")
					mycmd1 = decode1
				end
			end
		end
	end
	if not delim1 then
		local cmd1 = payload:tostring(1, -1)
		if cmd1 then
			--nw.logInfo("*** COMMAND: " .. cmd1 .. " ***")
			local decode1 = nw.base64Decode(cmd1)
			if decode1 then
				--nw.createMeta(self.keys["command"], decode1)
				--nw.logInfo("*** COMMAND1: " .. decode1 .. " ***")
				mycmd1 = decode1
			end
		end
	end
	if morez then
		local cmd2 = payload:tostring(morez + 4, -1)
		if cmd2 and string.len(cmd2) > 1000 then
			local decode2 = cmd2
			if decode2 then
				--nw.createMeta(self.keys["command"], decode2)
				--nw.logInfo("*** COMMAND2: " .. decode2 .. " ***")
				mycmd2 = decode2
			end
		else
			local decode2 = nw.base64Decode(cmd2)
			if decode2 then
				--nw.createMeta(self.keys["command"], decode2)
				--nw.logInfo("*** COMMAND2: " .. decode2 .. " ***")
				mycmd2 = decode2
			end
		end
	end
	if mycmd2 then
		local finalcmd = (mycmd1 .. " " .. mycmd2)
		nw.createMeta(self.keys["command"], finalcmd)
		--nw.logInfo("*** FINAL COMMAND: " .. finalcmd .. " ***")
	else
		local finalcmd = mycmd1
		nw.createMeta(self.keys["command"], finalcmd)
		--nw.logInfo("*** FINAL COMMAND: " .. finalcmd .. " ***")		
	end
end

--[[
function lua_chopperdecoded:tokenRESPONSE(token, first, last)
	current_position = last + 1
	local resppayload = nw.getPayload(current_position, -1)
	local mystart = resppayload:find("->|", 1, -1)	
	if mystart then
		--nw.logInfo("*** MYSTART FOUND ***")
		local myresponse = resppayload:tostring(mystart, -1)
		if myresponse then
			nw.logInfo("*** RESPONSE: " .. myresponse .. " ***")
		end
	end
end
--]]

-- Step 3 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
lua_chopperdecoded:setCallbacks({
	[nwevents.OnSessionBegin] = lua_chopperdecoded.sessionBegin,
	["BaSE64_dEcOdE&z1="] = lua_chopperdecoded.tokenDECODE,
	--["HTTP/1.1 200 OK"] = lua_chopperdecoded.tokenRESPONSE,
})
