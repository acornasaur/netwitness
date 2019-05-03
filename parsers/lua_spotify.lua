local lua_spotify = nw.createParser("lua_spotify", "Identify spotify traffic")

--[[
    DESCRIPTION

        Identify spotify network traffic and register into service.  
        

    VERSION
	
        2019-05-03 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		None
        
--]]




function lua_spotify:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_spotify:tokenMATCH(token, first, last)
	if first <= 10 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			current_position = last + 6
			local payload = nw.getPayload(current_position, current_position + 1)
			if payload and #payload == 2 then
				local check = payload:uint16(1, 2)
				if check == 40961 then
					local status, error = pcall(function()
					self.state = self.state or {}
					if not (self.state.identified or self.state.notspotify) then
						local service = nw.getAppType()
						if not service or service == 0 then
							nw.setAppType(4070)
							--nw.logInfo("*** SERVICE 4070 ***")
							self.state.identified = true
						elseif service ~= 4070 then
							self.state.notspotify = true
						end
					end
					end)
					if not status and debugParser then
						nw.logFailure(error)
					end	
				end	
			end	
		end
	end			
end

lua_spotify:setCallbacks({
	[nwevents.OnSessionBegin] = lua_spotify.sessionBegin,
	["\0\4\0\0\1"] = lua_spotify.tokenMATCH, -- 00 04 00 00 01
	["\0\4\0\0\0"] = lua_spotify.tokenMATCH, -- 00 04 00 00 00
})
