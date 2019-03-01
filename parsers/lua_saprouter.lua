local lua_saprouter = nw.createParser("lua_saprouter", "Identify saprouter traffic")

--[[
    DESCRIPTION

        Identify saprouter network traffic and register into service.  
        

    VERSION
	
        2018-07-24 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES

        
--]]




function lua_saprouter:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_saprouter:tokenMATCH(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 then
		local status, error = pcall(function()
		self.state = self.state or {}
		if not (self.state.identified or self.state.notsaprouter) then
			local service = nw.getAppType()
			if not service or service == 0 then
				nw.setAppType(3299)
				--nw.logInfo("*** SERVICE 3299 ***")
				self.state.identified = true
			elseif service ~= 3299 then
				self.state.notsaprouter = true
			end
		end
		end)
		if not status and debugParser then
			nw.logFailure(error)
		end		
	end				
end

lua_saprouter:setCallbacks({
	[nwevents.OnSessionBegin] = lua_saprouter.sessionBegin,
	["\0\0\0\76\78\73\95\82\79\85\84\69\0\2"] = lua_saprouter.tokenMATCH, -- 00 00 00 4c 4e 49 5f 52 4f 55 54 45 00 02
})


