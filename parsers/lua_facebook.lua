local lua_facebook = nw.createParser("lua_facebook", "Identify Facebook traffic")

--[[
    DESCRIPTION

        Identify Facebook network traffic and register into service.  
        

    VERSION
	
        2017-04-04 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
--]]




function lua_facebook:sessionBegin()
	-- reset parser_state for the new session
	fbreq = nil
	fbresp = nil
	self.state = nil
end

function lua_facebook:req(token, first, last)
	local protocol = nw.getTransport()
	if protocol == 6 then
		local requestStream = nwsession.getRequestStream()
		if requestStream then
			if fbresp == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notFT) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(3113)
						--nw.logInfo("*** SERVICE 3113 ***")
						self.state.identified = true
					elseif service ~= 3113 then
						self.state.notFT = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				fbreq = 1
			end
		end
	end				
end

function lua_facebook:resp(token, first, last)
	local protocol = nw.getTransport()
	if protocol == 6 then
		local responseStream = nwsession.getResponseStream()
		if responseStream then
			if fbreq == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notFT) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(3113)
						--nw.logInfo("*** SERVICE 3113 ***")
						self.state.identified = true
					elseif service ~= 3113 then
						self.state.notFT = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				fbresp = 1
			end
		end
	end				
end

function lua_facebook:req1(token, first, last)
	if first <= 10 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notkayesa) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(3113)
					--nw.logInfo("*** SERVICE 3113 ***")
					self.state.identified = true
				elseif service ~= 3113 then
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

lua_facebook:setCallbacks({
	[nwevents.OnSessionBegin] = lua_facebook.sessionBegin,
	["\49\81\84\86\48"] = lua_facebook.req, -- 31 51 54 56 30
	["\49\81\84\86\48\48\0\0\0\83\78\79\77\1"] = lua_facebook.resp, -- 31 51 54 56 30 30 00 00 00 53 4e 4f 4d 01
	["\69\68\0\1\0\0\4\8\5\8\2\87\65\2\1\0"] = lua_facebook.req1 -- 45 44 00 01 00 00 04 08 05 08 02 57 41 02 01 00 - facebook messenger/whatsapp
})




