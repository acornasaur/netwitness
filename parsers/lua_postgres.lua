local lua_postgres = nw.createParser("lua_postgres", "Identify postgres traffic")

--[[
    DESCRIPTION

        Identify postgres network traffic and register into service.  
        

    VERSION
	
        2019-04-26 - Initial development 
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
	
        
--]]

function lua_postgres:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_postgres:tokenMATCH(token, first, last)
	if first <= 10 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notpostgres) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(5433)
					--nw.logInfo("*** SERVICE 5433 ***")
					self.state.identified = true
				elseif service ~= 5433 then
					self.state.notpostgres = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end	
end

lua_postgres:setCallbacks({
	[nwevents.OnSessionBegin] = lua_postgres.sessionBegin,
	["\0\0\0\8\4\210\22\47"] = lua_postgres.tokenMATCH, -- 00 00 00 08 04 d2 16 2f
})
