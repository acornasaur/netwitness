local parserName = "fingerprint_deb"
local parserVersion = "2018.09.27.1"

local fingerprint_deb = nw.createParser(parserName, "debian package file detection")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Detect Debian package files.
]=]

--[=[
    VERSION

        2018.09.27    christopher.ahearn@rsa.com                   initial development


    OPTIONS

        "fixme" : default FIXME
        
            fixme


    IMPLEMENTATION
            
        https://en.wikipedia.org/wiki/Deb_(file_format)

        
    TODO
    
    
    NOTES
    
 		None

       

--]=]

summary.keyUsage = {
    ["filetype"] = "deb",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "file analysis",
}

fingerprint_deb:setKeys({
    nwlanguagekey.create("filetype")
})


function fingerprint_deb:magic(token, first, last)
	current_position = last + 49
	local payload = nw.getPayload(current_position, current_position + 15)
	if payload and #payload == 16 then
		local control = payload:find("control.tar", 1, -1)
		if control then			
			nw.createMeta(self.keys["filetype"], "deb")
		end
   	end
end


fingerprint_deb:setCallbacks({
    ["\33\60\97\114\99\104\62\10\100\101\98\105\97\110\45\98\105\110\97\114\121\32\32\32"] = fingerprint_deb.magic,    -- 21 3c 61 72 63 68 3e 0a 64 65 62 69 61 6e 2d 62 69 6e 61 72 79 20 20 20
})


return summary