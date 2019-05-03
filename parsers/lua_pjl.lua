local lua_pjl = nw.createParser("lua_pjl", "Identify pjl traffic")

--[[
    DESCRIPTION

        Identify Print Job Language network traffic and register into service.  
        

    VERSION
	
        2019-05-03 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		None
        
--]]




function lua_pjl:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_pjl:tokenMATCH(token, first, last)
	if first <= 32 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notpjl) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(9100)
					--nw.logInfo("*** SERVICE 9100 ***")
					self.state.identified = true
				elseif service ~= 9100 then
					self.state.notpjl = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end			
end

lua_pjl:setCallbacks({
	[nwevents.OnSessionBegin] = lua_pjl.sessionBegin,
	["\37\45\49\50\51\52\53\88\64\80\74\76\32\74\79\66\13\10"] = lua_pjl.tokenMATCH, -- 25 2d 31 32 33 34 35 58 40 50 4a 4c 20 4a 4f 42 
})
