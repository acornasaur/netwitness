local parserName = "ntp4_lua"
local parserVersion = "2019.05.07.1"

local ntpParser = nw.createParser(parserName, "Network Time Protocol")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Identifies Network Time Protocol.

Performs identification only.  No meta is extracted.
]=]

summary.dependencies = {
    ["parsers"] = {
        "NETWORK"
    }
}

summary.conflicts = {
    ["parsers"] = {
        "NTP"
    }
}

summary.keyUsage = {
    ["service"] = "'123'"
}

summary.liveTags = {
    "operations",
    "event analysis",
    "protocol analysis",
}

--[[
    VERSION

        2019.05.07    Chris Ahearn                             Initial development


    OPTIONS

        None


    IMPLEMENTATION
        
       


    TODO

        Alert if the Reference Timestamp in the response is far in the future or past?

--]]

function ntpParser:sessionBegin()
    self.sessionVars = {}
end

function ntpParser:onPort()
    if self.sessionVars.seen then
        return
    end
    self.sessionVars.seen = true
    local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 17 then
		local payload = nw.getPayload(1,2)
		if payload and payload:len() == 2 then
			local flags, stratum = payload:uint8(1, 2)
			if flags == 11 or flags == 12 or flags == 25 or flags == 27 or flags == 28 or flags == 35 or flags == 36 or flags == 227 and stratum then
				if stratum == 0 or stratum == 1 or stratum == 2 or stratum == 3 or stratum == 4 then
					nw.setAppType(123)
				end
			end
		end
    end
end

ntpParser:setCallbacks({
    [nwevents.OnSessionBegin] = ntpParser.sessionBegin,
    [123] = ntpParser.onPort
})

return summary