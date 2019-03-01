local parserName = "fingerprint_rpm"
local parserVersion = "2018.09.27.1"

local fingerprint_rpm = nw.createParser(parserName, "Linux RPM file detection")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Detect Linux RPM files.
]=]

--[=[
    VERSION

        2018.09.27    christopher.ahearn@rsa.com                   initial development


    OPTIONS

        "fixme" : default FIXME
        
            fixme


    IMPLEMENTATION
            
        http://ftp.rpm.org/max-rpm/s1-rpm-file-format-rpm-file-format.html

        
    TODO
    
    
    NOTES
    
 		None

       

--]=]

summary.keyUsage = {
    ["filetype"] = "rpm",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "file analysis",
}

fingerprint_rpm:setKeys({
    nwlanguagekey.create("filetype"),
    nwlanguagekey.create("filename"),
})


function fingerprint_rpm:magic(token, first, last)
	current_position = last + 1
	--filename should be within the next 66 bytes with a null delimiter.  Lets find it.
	local payload = nw.getPayload(current_position, current_position + 65)
	if payload and #payload == 66 then
		local nullfind = payload:find("\0", 1, -1)
		if nullfind then	
			nw.createMeta(self.keys["filetype"], "rpm")
			local filename = payload:tostring(1, nullfind -1)
			if filename then		
				nw.createMeta(self.keys["filename"], filename)
			end
		end
   	end
end


fingerprint_rpm:setCallbacks({
    ["\237\171\238\219\3\0\0\0\0\1"] = fingerprint_rpm.magic,    -- ed ab ee db 03 00 00 00 00 01
})


return summary