local lua_kayesa = nw.createParser("lua_kayesa", "Identify kayesa traffic")

--[[
    DESCRIPTION

        Identify kayesa network traffic and register into service.  
        

    VERSION
	
        2019-04-08 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		None
        
--]]




function lua_kayesa:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_kayesa:tokenMATCH(token, first, last)
	if first <= 10 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notkayesa) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(5721)
					--nw.logInfo("*** SERVICE 5721 ***")
					self.state.identified = true
				elseif service ~= 5721 then
					self.state.notkayesa = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end			
end

lua_kayesa:setCallbacks({
	[nwevents.OnSessionBegin] = lua_kayesa.sessionBegin,
	["\74\94\122\4\0\0"] = lua_kayesa.tokenMATCH, -- 4a 5e 7a 04 00 00 
})
