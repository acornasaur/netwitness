local lua_meraki = nw.createParser("lua_meraki", "Identify meraki traffic")

--[[
    DESCRIPTION

        Identify meraki network traffic and register into service.  
        

    VERSION
	
        2018-02-18 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
--]]




function lua_meraki:sessionBegin()
	-- reset parser_state for the new session
	merakireq = nil
	merakiresp = nil
	self.state = nil
end

function lua_meraki:req(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 17 and srcPort > 1024 and dstPort == 7351 then
		local requestStream = nwsession.getRequestStream()
		if requestStream then
			if merakiresp == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notMERAKI) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(7351)
						--nw.logInfo("*** SERVICE 7351 ***")
						self.state.identified = true
					elseif service ~= 7351 then
						self.state.notMERAKI = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				merakireq = 1
			end
		end
	end				
end

function lua_meraki:resp(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 17 and srcPort > 1024 and dstPort == 7351 then
		local responseStream = nwsession.getResponseStream()
		if responseStream then
			if merakireq == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notMERAKI) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(7351)
						--nw.logInfo("*** SERVICE 7351 ***")
						self.state.identified = true
					elseif service ~= 7351 then
						self.state.notMERAKI = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				merakiresp = 1
			end
		end
	end				
end

lua_meraki:setCallbacks({
	[nwevents.OnSessionBegin] = lua_meraki.sessionBegin,
	["\254\247\40\145\13\01\00\112"] = lua_meraki.req, -- fe f7 28 91 0d 01 00 70
	["\254\247\40\145\13\01\00\46"] = lua_meraki.resp, -- fe f7 28 91 0d 01 00 2e
})


