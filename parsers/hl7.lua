local parserName = "hl7"
local parserVersion = "2018.08.23.1d1"

local teamviewer = nw.createParser(parserName, "Identify HL7 traffic", 6046)

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Identify HL7 traffic.

Performs identification only.  No meta is extracted.
]=]

--[=[
    DESCRIPTION

        Identify hl7 network traffic and register into service.  
        

    VERSION
	
        2018-07-18 - Initial development
		2018-07-20 - Found additional traffic associated with other tools. 
					 Adjusting tokens and functions for service identification
		2018-08-23 - Reformatted parser for Live content submission
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
    	Thanks to @j3rmbadger on this nice find.
		Thanks to @j3rmbadger on this nice find AGAIN@!@!@!.
		https://www.tripwire.com/state-of-security/security-data-protection/hl7-data-interfaces-in-medical-environments/
--]=]

summary.dependencies = {
    ["parsers"] = {
        "NETWORK",
    }
}

summary.keyUsage = {
    ["service"] = "'6046'",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "protocol analysis",
}


function hl7:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function hl7:tokenMATCH(token, first, last)
	if first <= 100 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.nothl7) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(6046)
					--nw.logInfo("*** SERVICE 6046 ***")
					self.state.identified = true
				elseif service ~= 6046 then
					self.state.nothl7 = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end		
		end	
	end			
end

hl7:setCallbacks({
	[nwevents.OnSessionBegin] = hl7.sessionBegin,
	["\11\77\83\72\124\94\126\47\38\124"] = hl7.tokenMATCH, -- .MSH|^~/&|
	["\11\77\83\72\124\94\126\92\38\124"] = hl7.tokenMATCH, -- .MSH|^~\&|
})

return summary