local lua_sapsgs = nw.createParser("lua_sapsgs", "Identify sap-sgs traffic")

--[[
    DESCRIPTION

        Identify sap-sgs network traffic and register into service.  
        

    VERSION
	
        2019-06-04 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		None
        
--]]




function lua_sapsgs:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_sapsgs:tokenMATCH(token, first, last)
	if first <= 4096 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notsapsgs) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(4825)
					--nw.logInfo("*** SERVICE 4825 ***")
					self.state.identified = true
				elseif service ~= 4825 then
					self.state.notsapsgs = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end			
end

lua_sapsgs:setCallbacks({
	[nwevents.OnSessionBegin] = lua_sapsgs.sessionBegin,
	["\0\0\0\64\2\3\10\145\96\217\0\0\0\0\106\97\118\97"] = lua_sapsgs.tokenMATCH, -- 00 00 00 40 02 03 0a 91 60 d9 00 00 00 00 6a 61 76 61
	["\0\0\0\0\106\97\118\97\0\0\0\0\0\0"] = lua_sapsgs.tokenMATCH, -- 00 00 00 00 6a 61 76 61 00 00 00 00 00 00 
	["\0\0\0\80\6\1\2\0\255\255\0\0\0"] = lua_sapsgs.tokenMATCH, -- 00 00 00 50 06 01 02 00 ff ff 00 00 00
	["\0\0\0\80\6\5\2\0\255\255\0\0\0"] = lua_sapsgs.tokenMATCH, -- 00 00 00 50 06 05 02 00 ff ff 00 00 00
	["\6\203\2\0\255\255\0\0\0\0"] = lua_sapsgs.tokenMATCH, -- 06 cb 02 00 ff ff 00 00 00 00
})

