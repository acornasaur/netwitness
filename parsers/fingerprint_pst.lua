local parserName = "fingerprint_pst"
local parserVersion = "2018.09.27.1"

local fingerprint_pst = nw.createParser(parserName, "Outlook PST file detection")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Detect Outlook PST files.
]=]

--[=[
    VERSION

        2018.09.27    christopher.ahearn@rsa.com                   initial development


    OPTIONS

        "fixme" : default FIXME
        
            fixme


    IMPLEMENTATION
            
        https://msdn.microsoft.com/en-us/library/ff387474(v=office.12).aspx

        
    TODO
    
    
    NOTES
    
 		None

       

--]=]

summary.keyUsage = {
    ["filetype"] = "pst",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "file analysis",
}

fingerprint_pst:setKeys({
    nwlanguagekey.create("filetype")
})


function fingerprint_pst:magic(token, first, last)
	current_position = last + 5
	local payload = nw.getPayload(current_position, current_position + 7)
	if payload and #payload == 8 then
		local magicclientf, magicclientl = payload:find("\83\77", 1, -1)
		if magicclientl then	
			local platform = payload:find("\1\1", magicclientl + 5, -1)
			if platform then		
				nw.createMeta(self.keys["filetype"], "pst")
			end
		end
   	end
end


fingerprint_pst:setCallbacks({
    ["\33\66\68\78"] = fingerprint_pst.magic,    -- 21 42 44 4E
})


return summary