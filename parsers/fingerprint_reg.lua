local parserName = "fingerprint_reg"
local parserVersion = "2018.08.16.1"

local fingerprint_reg = nw.createParser(parserName, "registry file detection")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Detect Windows Registry files.
]=]

--[=[
    VERSION

        2018.08.16    christopher.ahearn@rsa.com                   initial development


    OPTIONS

        "fixme" : default FIXME
        
            fixme


    IMPLEMENTATION
            
        https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md

        
    TODO
    
    
    NOTES
    
    	minor versions 
		3 = 50331648
		4 = 67108864
		5 = 83886080
		6 = 100663296

       

--]=]

summary.keyUsage = {
    ["filetype"] = "registry hive",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "file analysis",
}

fingerprint_reg:setKeys({
    nwlanguagekey.create("filetype")
})


function fingerprint_reg:magic(token, first, last)
	current_position = last + 17
	local payload = nw.getPayload(current_position, current_position + 7)
	if payload and #payload == 8 then
		local majorversion = payload:uint32(1, 4)
		if majorversion == 16777216 then
			local minorversion = payload:uint32(5, 8)
			if minorversion == 50331648 or minorversion == 67108864 or minorversion == 83886080 or minorversion == 100663296 then
				nw.createMeta(self.keys["filetype"], "registry hive")
			end
		end
   	end
end


fingerprint_reg:setCallbacks({
    ["\114\101\103\102"] = fingerprint_reg.magic,    -- regf
})


return summary