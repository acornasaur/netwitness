local lua_mccf = nw.createParser("lua_mccf", "Identify Media Control Channel Framework traffic")

--[[
    DESCRIPTION

        Identify Media Control Channel Framework network traffic and register into service.  
        

    VERSION
	
        2019-06-04 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		None
        
--]]




function lua_mccf:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_mccf:tokenMATCH(token, first, last)
	if first <= 100 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notmccf) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(7563)
					--nw.logInfo("*** SERVICE 7563 ***")
					self.state.identified = true
				elseif service ~= 7563 then
					self.state.notmccf = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end			
end

lua_mccf:setCallbacks({
	[nwevents.OnSessionBegin] = lua_mccf.sessionBegin,
	["\32\83\89\78\67\10\68\105\97\108\111\103\45\105\100\58\32"] = lua_mccf.tokenMATCH, -- 20 53 59 4e 43 0a 44 69 61 6c 6f 67 2d 69 64 3a 20
})

