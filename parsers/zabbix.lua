local parserName = "zabbix"
local parserVersion = "2018.08.14.1d1"

local zabbix = nw.createParser(parserName, "zabbix protocol identification", 10051)

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Identifies zabbix sessions.

Performs identification only.  No meta is extracted.
]=]

--[=[
    VERSION

        2018.08.14.1  christopher.ahearn@rsa.com                   initial development


    OPTIONS

        none


    IMPLEMENTATION

        none


    TODO

        none?

--]=]


summary.dependencies = {
    ["parsers"] = {
        "NETWORK",
    }
}

summary.keyUsage = {
    ["service"] = "'10051'",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "protocol analysis",
}

function zabbix:sessionBegin()
	-- reset parser_state for the new session
	zabbixreq = nil
	zabbixresp = nil
	self.state = nil
end

function zabbix:req(token, first, last)
	-- Only interested if token matched within the first 100 bytes of payload
	if first <= 100 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local requestStream = nwsession.getRequestStream()
			if requestStream then
				--nw.logInfo("*** ZABBIX REQUEST TOKEN MATCH: " .. token .. " ***")
				if zabbixresp == 1 then
					local status, error = pcall(function()
					self.state = self.state or {}
					if not (self.state.identified or self.state.notZABBIX) then
						local service = nw.getAppType()
						if not service or service == 0 then
							nw.setAppType(10051)
							--nw.logInfo("*** SERVICE 10051 ***")
							self.state.identified = true
						elseif service ~= 10051 then
							self.state.notZABBIX = true
						end
					end
					end)
					if not status and debugParser then
						nw.logFailure(error)
					end
				else
					zabbixreq = 1
				end
			end
		end		
	end		
end

function zabbix:resp(token, first, last)
	-- Only interested if token matched within the first 100 bytes of payload
	if first <= 100 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local responseStream = nwsession.getResponseStream()
			if responseStream then
				--nw.logInfo("*** ZABBIX RESPONSE TOKEN MATCH: " .. token .. " ***")
				if zabbixreq == 1 then
					local status, error = pcall(function()
					self.state = self.state or {}
					if not (self.state.identified or self.state.notZABBIX) then
						local service = nw.getAppType()
						if not service or service == 0 then
							nw.setAppType(10051)
							--nw.logInfo("*** SERVICE 10051 ***")
							self.state.identified = true
						elseif service ~= 10051 then
							self.state.notZABBIX = true
						end
					end
					end)
					if not status and debugParser then
						nw.logFailure(error)
					end
				else
					zabbixresp = 1
				end
			end
		end	
	end			
end

zabbix:setCallbacks({
	[nwevents.OnSessionBegin] = zabbix.sessionBegin,
	["\90\66\88\68\01"] = zabbix.req, -- 5a 42 58 44 01
	["\123\10\09\34\114\101\113\117\101\115\116\34\58"] = zabbix.req, -- 7b 0a 09 22 72 65 71 75 65 73 74 22 3a
	["\34\114\101\113\117\101\115\116\34\58"] = zabbix.req, -- "request":	
	["\90\66\88\68\01"] = zabbix.resp, -- 5a 42 58 44 01
	["\34\100\97\116\97\34\58\91\93"] = zabbix.resp, -- "data":[]
})

return summary


