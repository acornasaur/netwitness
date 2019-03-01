local parserName = "mypayload"
local parserVersion = "2018.08.14.1d1"

local mypayload = nw.createParser(parserName, "Grabs the first 256 bytes of payload")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Grabs the first 256 bytes of payload

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


summary.liveTags = {
    "operations",
    "event analysis",
    "protocol analysis",
}

mypayload:setKeys({
	nwlanguagekey.create("payload.tx", nwtypes.Text),
	nwlanguagekey.create("payload.rx", nwtypes.Text),
})

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function mypayload:sessionBegin()
	-- reset parser_state for the new session
	payhexreq = nil
	payhexresp = nil

	local requestStream = nwsession.getRequestStream()
	local responseStream = nwsession.getResponseStream()
	if requestStream then
		local payload = nw.getPayload(requestStream,1,256)
		if payload then
			local paytemp = payload:tostring(1, -1)
			if paytemp then
				local payhex = string.tohex(paytemp)
				if payhex then
					payhexreq = payhex
					--nw.createMeta(self.keys["payload.tx"], payhex)
					--nw.logInfo("*** MYPAYLOAD: " .. payhex .. " ***")
				end
			end
		end
	end
	if responseStream then
		local payload = nw.getPayload(responseStream,1,256)
		if payload then
			local paytemp = payload:tostring(1, -1)
			if paytemp then
				local payhex = string.tohex(paytemp)
				if payhex then
					payhexresp = payhex
					--nw.createMeta(self.keys["payload.rx"], payhex)
					--nw.logInfo("*** MYPAYLOAD: " .. payhex .. " ***")
				end
			end
		end
	end
end

function mypayload:sessionEnd()
	local service = nw.getAppType()
	if service == 0 then
		if payhexreq then
			nw.createMeta(self.keys["payload.tx"], payhexreq)
		end
		if payhexresp then
			nw.createMeta(self.keys["payload.rx"], payhexresp)
		end
	end
end

mypayload:setCallbacks({
	[nwevents.OnSessionBegin] = mypayload.sessionBegin,
	[nwevents.OnSessionEnd] = mypayload.sessionEnd,
})

return summary


