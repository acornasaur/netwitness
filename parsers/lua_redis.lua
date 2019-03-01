local lua_redis = nw.createParser("lua_redis", "Identify REDIS RESP traffic")

--[[
    DESCRIPTION

        Identify REDIS RESP network traffic and register into service.  
        

    VERSION
	
        2018-02-17 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
--]]




function lua_redis:sessionBegin()
	-- reset parser_state for the new session
	redisreq = nil
	redisresp = nil
	self.state = nil
end

function lua_redis:req(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 and dstPort == 6379 then
		local requestStream = nwsession.getRequestStream()
		if requestStream then
			if redisresp == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notFT) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(6379)
						--nw.logInfo("*** SERVICE 6379 ***")
						self.state.identified = true
					elseif service ~= 6379 then
						self.state.notREDIS = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				redisreq = 1
			end
		end
	end				
end

function lua_redis:resp(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 and dstPort == 6379 then
		local responseStream = nwsession.getResponseStream()
		if responseStream then
			if redisreq == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notREDIS) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(6379)
						--nw.logInfo("*** SERVICE 6379 ***")
						self.state.identified = true
					elseif service ~= 6379 then
						self.state.notREDIS = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				redisresp = 1
			end
		end
	end				
end

lua_redis:setCallbacks({
	[nwevents.OnSessionBegin] = lua_redis.sessionBegin,
	["\42\50\13\10\36\52\13\10"] = lua_redis.req, -- 2a 32 0d 0a 24 34 0d 0a
	["\43\79\75\13\10\43\79\75"] = lua_redis.resp, -- 2b 4f 4b 0d 0a 2b 4f 4b
})