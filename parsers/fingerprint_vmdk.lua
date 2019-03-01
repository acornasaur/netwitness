local parserName = "fingerprint_vmdk"
local parserVersion = "2018.08.16.1"

local fingerprint_vmdk = nw.createParser(parserName, "registry file detection")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Detect VMWare VMDK files.
]=]

--[=[
    VERSION

        2018.09.26    christopher.ahearn@rsa.com                   initial development


    OPTIONS

        "fixme" : default FIXME
        
            fixme


    IMPLEMENTATION
            
        https://www.vmware.com/support/developer/vddk/vmdk_50_technote.pdf

        
    TODO
    
    
    NOTES
    
 		None

       

--]=]

summary.keyUsage = {
    ["filetype"] = "vmdk",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "file analysis",
}

fingerprint_vmdk:setKeys({
    nwlanguagekey.create("filetype")
})


function fingerprint_vmdk:magic(token, first, last)
	current_position = last + 37
	local payload = nw.getPayload(current_position, current_position + 1)
	if payload and #payload == 2 then
		local numGTEsPerGT = payload:uint16(1, 2)
		if numGTEsPerGT == 2 then
			nw.createMeta(self.keys["filetype"], "vmdk")
		end
   	end
end


fingerprint_vmdk:setCallbacks({
    ["\75\68\77\86\1\0\0\0"] = fingerprint_vmdk.magic,    -- 4b44 4d56 0100 0000
    ["\75\68\77\86\2\0\0\0"] = fingerprint_vmdk.magic,    -- 4b44 4d56 0200 0000
})


return summary