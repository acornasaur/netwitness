local lua_facetime = nw.createParser("lua_facetime", "Identify Apple Facetime traffic")

--[[
    DESCRIPTION

        Identify Apple Facetime network traffic and register into service


    VERSION

        2017-03-31 - Initial development


    AUTHOR

        christopher.ahearn@rsa.com


    DEPENDENCIES

        None

--]]




function lua_facetime:sessionBegin()
	-- reset parser_state for the new session
	stun = nil
	self.state = nil
end

function lua_facetime:stun(token, first, last)
	local protocol, srcPort, dstPort = nw.getTransport()
	if protocol == 17 and srcPort > 1024 and dstPort > 1024 then
		-- found STUN
		stun = 1
		--nw.logInfo("*** STUN SET ***")
	end
end

function lua_facetime:protocol()
	if stun == 1 then
		--nw.logInfo("*** PROTOCOL TOKEN MATCH ***")
		local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notFT) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(16402)
					--nw.logInfo("*** SERVICE 16402 ***")
					self.state.identified = true
				elseif service ~= 16402 then
					self.state.notFT = true
				end
			end
		end)
		if not status and debugParser then
				nw.logFailure(error)
		end
	end
end



lua_facetime:setCallbacks({
        [nwevents.OnSessionBegin] = lua_facetime.sessionBegin,
        ["\0\25\0\4\17\0\0\0"] = lua_facetime.stun, -- 00 19 00 04 11 00 00 00
        ["\085\115\101\114\045\065\103\101\110\116\058\032\086\105\099\101\114\111\121"] = lua_facetime.protocol,
})