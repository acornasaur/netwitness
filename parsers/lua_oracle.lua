local lua_oracle = nw.createParser("lua_oracle", "Identify oracle traffic")

--[[
    DESCRIPTION

        Identify oracle network traffic and register into service.  
        

    VERSION
	
        2019-05-21 - Initial development 
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
	
        
--]]

function lua_oracle:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_oracle:tokenMATCH(token, first, last)
	if first <= 64 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notoracle) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(6390)
					--nw.logInfo("*** SERVICE 6390 ***")
					self.state.identified = true
				elseif service ~= 6390 then
					self.state.notoracle = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end	
end

lua_oracle:setCallbacks({
	[nwevents.OnSessionBegin] = lua_oracle.sessionBegin,
	["\48\129\137\2\1\2\99\1"] = lua_oracle.tokenMATCH, -- 30 81 89 02 01 02 63 
	["\48\12\2\1\1\96\7\2\1\3"] = lua_oracle.tokenMATCH, -- 30 0c 02 01 01 60 07 02 01 03
})
