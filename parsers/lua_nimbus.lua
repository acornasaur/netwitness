local lua_nimbus = nw.createParser("lua_nimbus", "Identify nimbus traffic")

--[[
    DESCRIPTION

        Identify nimbus network traffic and register into service.  
        

    VERSION
	
        2019-04-26 - Initial development 
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
	
        
--]]

function lua_nimbus:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_nimbus:tokenMATCH(token, first, last)
	if first <= 10 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notnimbus) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(48002)
					--nw.logInfo("*** SERVICE 48002 ***")
					self.state.identified = true
				elseif service ~= 48002 then
					self.state.notnimbus = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end	
end

lua_nimbus:setCallbacks({
	[nwevents.OnSessionBegin] = lua_nimbus.sessionBegin,
	["\110\105\109\98\117\115\47\49"] = lua_nimbus.tokenMATCH, -- 6e 69 6d 62 75 73 2f 31
})
