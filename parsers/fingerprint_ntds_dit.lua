local parserName = "fingerprint_ntds_dit"
local parserVersion = "2018.08.20.1"

local fingerprint_ntds_dit = nw.createParser(parserName, "ntds.dit file detection")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Detect the Active Directory Database ntds.dit files.
]=]

--[=[
    VERSION

        2018.08.20    christopher.ahearn@rsa.com                   initial development


    OPTIONS

        "fixme" : default FIXME
        
            fixme


    IMPLEMENTATION
            


        
    TODO
    
    
    NOTES


       

--]=]

summary.keyUsage = {
    ["filetype"] = "ntds_dit",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "file analysis",
}

fingerprint_ntds_dit:setKeys({
    nwlanguagekey.create("filetype")
})

function fingerprint_ntds_dit:sessionBegin()
	-- reset parser_state for the new session
	theditheader = nil
	sysobj = nil
end


function fingerprint_ntds_dit:theditheader(token, first, last)
	if sysobj == 1 then
		nw.createMeta(self.keys["filetype"], "ntds_dit")
	else
		theditheader = 1
	end
end

function fingerprint_ntds_dit:theditsysobj(token, first, last)
	if theditheader == 1 then
		nw.createMeta(self.keys["filetype"], "ntds_dit")
	else
		sysobj = 1
	end
end

fingerprint_ntds_dit:setCallbacks({
	[nwevents.OnSessionBegin] = fingerprint_ntds_dit.sessionBegin,
    ["\239\205\171\137\32\6"] = fingerprint_ntds_dit.theditheader,    -- ef cd ab 89 20 06
   	["\83\121\115\79\98\106\101\99\116\115\13\0"] = fingerprint_ntds_dit.theditsysobj,    -- 53 79 73 4f 62 6a 65 63 74 73 0d 00 MSysObjects
})


return summary