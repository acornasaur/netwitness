local lua_msdnav = nw.createParser("lua_msdnav", "Identify Microsoft Dynamics NAV Server traffic")

--[[
    DESCRIPTION

        Identify Microsoft Dynamics NAV Server network traffic and register into service.  
        

    VERSION
	
        2019-05-03 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES

        
--]]

-- Write meta into the following meta key(s)
lua_msdnav:setKeys({
	nwlanguagekey.create("directory",nwtypes.Text),
	nwlanguagekey.create("alias.host",nwtypes.Text),
})


function lua_msdnav:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_msdnav:tokenMATCH(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 then
		current_position = last + 1
		local payload = nw.getPayload(current_position, current_position + 128) -- only getting payload that i need
		local delim1f, delim1l = payload:find(":7046", 1, -1)
		if delim1f then
			-- Set the Service Type
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notmsdnav) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(7046)
					--nw.logInfo("*** SERVICE 7046 ***")
					self.state.identified = true
				elseif service ~= 7046 then
					self.state.notmsdnav = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
			
			delim1f = delim1f - 1
			local host = payload:tostring(1, delim1f)
			if host then
				nw.createMeta(self.keys["alias.host"], host)
			end
			current_position = delim1l + 1
			local delim2f, delim2l = payload:find("\3\8\9\21", current_position, -1) -- 1 is the first byte, -1 is the last byte
			--if we found the delim
			if delim2f then
				--we don't want to read the delim
				delim2f = delim2f - 1
				local string_temp = payload:tostring(current_position, delim2f)
				--make sure the read succeeded
				if string_temp then
					-- register what was read as meta
					nw.createMeta(self.keys["directory"], string_temp)
				end
			end
		end		
	end				
end

lua_msdnav:setCallbacks({
	[nwevents.OnSessionBegin] = lua_msdnav.sessionBegin,
	["net.tcp://"] = lua_msdnav.tokenMATCH,
})
