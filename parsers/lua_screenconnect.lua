local lua_screenconnect = nw.createParser("lua_screenconnect", "Identify screenconnect traffic")

--[[
    DESCRIPTION

        Identify screenconnect network traffic and register into service.  
        

    VERSION
	
        2019-04-24 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		This was based on known compromised version.
		https://www.virustotal.com/#/file/2884b04cacb7e30c9a73b4a3866fb3be167bf13b5d7994bc28153ce278f7f070/detection
		
		Still need to compare against known good ScreenConnect traffic.
        
--]]




function lua_screenconnect:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_screenconnect:tokenMATCH(token, first, last)
	if first <= 10 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notscreenconnect) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(7310)
					--nw.logInfo("*** SERVICE 7310 ***")
					self.state.identified = true
				elseif service ~= 7310 then
					self.state.notscreenconnect = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end			
end

lua_screenconnect:setCallbacks({
	[nwevents.OnSessionBegin] = lua_screenconnect.sessionBegin,
	["\115\16\0\0\0\0\0\0\0\0\0\0\0\0\0\0"] = lua_screenconnect.tokenMATCH, -- 73 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00
})
