local lua_kaspersky = nw.createParser("lua_kaspersky", "Identify Kaspersky update traffic")

--[[
    DESCRIPTION

        Identify Kaspersky Update network traffic and register into service.  
        

    VERSION
	
        2018-02-23 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    META
    
    	Registers "service = 1997"
        
--]]




function lua_kaspersky:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_kaspersky:req(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 then
		local requestStream = nwsession.getRequestStream()
		if requestStream then
			--nw.logInfo("*** KASPERSKY TOKEN MATCH ***")
			current_position = last + 9
			local helloPayload = nw.getPayload(current_position, current_position + 3)
			if helloPayload then
				local ipheaderpos = helloPayload:find("\001\000\000\000", 1, -1)
				--nw.logInfo("*** KASPERSKY FOUND TRAILER ***")
				if ipheaderpos then
					local status, error = pcall(function()
					self.state = self.state or {}
					if not (self.state.identified or self.state.notKASPERSKY) then
						local service = nw.getAppType()
						if not service or service == 0 then
							nw.setAppType(1997)
							--nw.logInfo("*** SERVICE 1997 ***")
							self.state.identified = true
						elseif service ~= 1997 then
							self.state.notKASPERSKY = true
						end
					end
					end)
					if not status and debugParser then
						nw.logFailure(error)
					end
				end
			end

		end
	end				
end



lua_kaspersky:setCallbacks({
	[nwevents.OnSessionBegin] = lua_kaspersky.sessionBegin,
	["\75\69\00\00"] = lua_kaspersky.req, -- 4b 45 00 00
})