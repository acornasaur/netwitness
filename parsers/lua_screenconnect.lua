local lua_screenconnect = nw.createParser("lua_screenconnect", "Identify screenconnect traffic")

--[[
    DESCRIPTION

        Identify screenconnect network traffic and register into service.  
        

    VERSION
	
        2019-04-24 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		This was based on known compromised version.
		https://www.virustotal.com/#/file/2884b04cacb7e30c9a73b4a3866fb3be167bf13b5d7994bc28153ce278f7f070/detection
		
		Still need to compare against known good ScreenConnect traffic.
        
--]]

lua_screenconnect:setKeys({
    nwlanguagekey.create("alias.host",nwtypes.Text),
    nwlanguagekey.create("alias.ip",nwtypes.IPv4),
})

local nwll = require('nwll')

function lua_screenconnect:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
	host = nil
	key = nil
end

function lua_screenconnect:tokenMATCH(token, first, last)
	if first <= 10 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notscreenconnect) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(7310)
					--nw.logInfo("*** SERVICE 7310 ***")
					self.state.identified = true
				elseif service ~= 7310 then
					self.state.notscreenconnect = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end	
	
	current_position = last + 1
	local payload = nw.getPayload(current_position, current_position + 64)
	if payload then
		local tag1 = payload:uint8(1,1)
		if tag1 == 4 then
			--nw.logInfo("*** TAG 4 ***")
			local start = 7
			local num_temp = payload:find("\1", start + 1, -1)
			if num_temp then
				--nw.logInfo("*** 4: FOUND NUM_TEMP ***")
				local myhost = payload:tostring(start, num_temp -1)
				if myhost then
					--nw.logInfo("*** 4 MYHOST: " .. myhost .. " ***")
					host, key = nwll.determineHostType(myhost)
					if host and key then
						nw.createMeta(self.keys[key], host)
					end
				end
			end
		end
		if tag1 == 6 then
			--nw.logInfo("*** TAG 6 ***")
			local start = 9
			local num_temp = payload:find("\2", start + 1, -1)
			if num_temp then
				--nw.logInfo("*** 6: FOUND NUM_TEMP ***")
				local myhost = payload:tostring(start, num_temp -1)
				if myhost then
					--nw.logInfo("*** 6 MYHOST: " .. myhost .. " ***")
					host, key = nwll.determineHostType(myhost)
					if host and key then
						nw.createMeta(self.keys[key], host)
					end
				end
			end
		end
	end	
end

lua_screenconnect:setCallbacks({
	[nwevents.OnSessionBegin] = lua_screenconnect.sessionBegin,
	["\115\16\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"] = lua_screenconnect.tokenMATCH, -- 73 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
})
