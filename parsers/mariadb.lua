local parserName = "redis"
local parserVersion = "2018.08.14.1d1"

local redis = nw.createParser(parserName, "redis protocol identification", 6379)

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Identifies redis sessions.

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
    ["service"] = "'6379'",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "protocol analysis",
}

function redis:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function redis:token(token, first, last)
	-- Only interested if token matched within the first 100 bytes of payload
	if first <= 100 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6  then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notREDIS) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(6379)
					nw.logInfo("*** SERVICE 6379 ***")
					self.state.identified = true
				elseif service ~= 6379 then
					self.state.notREDIS = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end		
	end		
end


redis:setCallbacks({
	[nwevents.OnSessionBegin] = redis.sessionBegin,
	["\42\50\13\10\36\52\13\10"] = redis.token, -- 2a 32 0d 0a 24 34 0d 0a
	["\42\51\13\10\36\56\13\10"] = redis.token, -- 2a 33 0d 0a 24 38 0d 0a
	["\43\79\75\13\10\43\79\75"] = redis.token, -- 2b 4f 4b 0d 0a 2b 4f 4b
	["\43\49\13\10\36\52\13\10"] = redis.token, -- 2a 31 0d 0a 24 34 0d 0a
})

return summary
