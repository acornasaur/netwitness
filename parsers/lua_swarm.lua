local lua_swarm = nw.createParser("lua_swarm", "Identify swarm traffic")

--[[
    DESCRIPTION

        Identify SWARM network traffic and register into service.  
        

    VERSION
	
        2019-05-03 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		None
        
--]]




function lua_swarm:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_swarm:tokenMATCH(token, first, last)
	if first <= 32 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notswarm) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(7680)
					--nw.logInfo("*** SERVICE 7680 ***")
					self.state.identified = true
				elseif service ~= 7680 then
					self.state.notswarm = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end			
end

lua_swarm:setCallbacks({
	[nwevents.OnSessionBegin] = lua_swarm.sessionBegin,
	["\14\83\119\97\114\109\32\112\114\111\116\111\99\111\108\0"] = lua_swarm.tokenMATCH, -- 0e 53 77 61 72 6d 20 70 72 6f 74 6f 63 6f 6c 00 
})
