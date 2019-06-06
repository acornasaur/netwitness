local lua_spnego = nw.createParser("lua_spnego", "Identify spnego traffic")

--[[
    DESCRIPTION

        Identify spnego network traffic and register into service.  
        

    VERSION
	
        2019-06-04 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		None
        
--]]




function lua_spnego:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_spnego:tokenMATCH(token, first, last)
	if first <= 512 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notspnego) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(3084)
					--nw.logInfo("*** SERVICE 3084 ***")
					self.state.identified = true
				elseif service ~= 3084 then
					self.state.notspnego = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end			
end

lua_spnego:setCallbacks({
	[nwevents.OnSessionBegin] = lua_spnego.sessionBegin,
	["\48\132\0\0\0\76\2\3"] = lua_spnego.tokenMATCH, -- 30 84 00 00 00 4c 02 03
})
