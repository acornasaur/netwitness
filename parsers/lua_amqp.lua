local lua_amqp = nw.createParser("lua_amqp", "Identify RabbitMQ traffic")

--[[
    DESCRIPTION

        Identify RabbitMPQnetwork traffic and register into service.  
        

    VERSION
	
        2018-02-17 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
--]]




function lua_amqp:sessionBegin()
	-- reset parser_state for the new session
	amqpreq = nil
	amqpresp = nil
	self.state = nil
end

function lua_amqp:req(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 and dstPort == 5672 then
		local requestStream = nwsession.getRequestStream()
		if requestStream then
			if amqpresp == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notFT) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(5672)
						--nw.logInfo("*** SERVICE 5672 ***")
						self.state.identified = true
					elseif service ~= 5672 then
						self.state.notAMQP = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				amqpreq = 1
			end
		end
	end				
end

function lua_amqp:resp(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 and dstPort == 5672 then
		local responseStream = nwsession.getResponseStream()
		if responseStream then
			if amqpreq == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notAMQP) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(5672)
						--nw.logInfo("*** SERVICE 5672 ***")
						self.state.identified = true
					elseif service ~= 5672 then
						self.state.notAMQP = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				amqpresp = 1
			end
		end
	end				
end

lua_amqp:setCallbacks({
	[nwevents.OnSessionBegin] = lua_amqp.sessionBegin,
	["\65\77\81\80\00\00\09\01"] = lua_amqp.req, -- 41 4d 51 50 00 00 09 01
	["\01\00\00\00\00\01\204\00"] = lua_amqp.resp, -- 01 00 00 00 00 01 cc 00
})