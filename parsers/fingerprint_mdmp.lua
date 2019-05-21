local parserName = "fingerprint_mdmp"
local parserVersion = "2019.05.21.1"

local fingerprint_mdmp = nw.createParser(parserName, "minidump file detection")

nw.logDebug(parserName .. " " .. parserVersion)

local summary = {["parserName"] = parserName, ["parserVersion"] = parserVersion}

summary.parserDetails = [=[
Detect Windows Minidump files.
]=]

--[=[
    VERSION

        2019.05.21    christopher.ahearn@rsa.com                   initial development


    OPTIONS

        "fixme" : default FIXME
        
            fixme


    IMPLEMENTATION
            
        https://github.com/libyal/libmdmp/blob/master/documentation/Minidump%20(MDMP)%20format.asciidoc

        
    TODO
    
    
    NOTES


       

--]=]

summary.keyUsage = {
    ["filetype"] = "minidump",
}

summary.liveTags = {
    "operations",
    "event analysis",
    "file analysis",
}

fingerprint_mdmp:setKeys({
    nwlanguagekey.create("filetype"),
    nwlanguagekey.create("ioc"),
})


function fingerprint_mdmp:magic(token, first, last)
	current_position = last + 11
	local payload = nw.getPayload(current_position, current_position + 3)
	if payload and #payload == 4 then
		local checksum = payload:uint32(1, 4)
		if checksum == 0 then
			current_position = last + 23
			local payload2 = nw.getPayload(current_position, current_position + 3)
			local fileflag = payload2:uint32(1, 4)
			if fileflag == 0 or fileflag == 1 or fileflag == 2 or fileflag == 4  or fileflag == 8 or fileflag == 16 or fileflag == 32 or fileflag == 64 or fileflag == 128 or fileflag == 256 or fileflag == 512 or fileflag == 1024 or fileflag == 2048 or fileflag == 4096 or fileflag == 8192 or fileflag == 16384 or fileflag == 32768 or fileflag == 65536 or fileflag == 131072 or fileflag == 262144 or fileflag == 524288 or fileflag == 1048576 then
				nw.createMeta(self.keys["filetype"], "minidump")
				local payload3 = nw.getPayload(current_position, current_position + 65535)
				if payload3 then
					local match = payload3:find("\108\0\115\0\97\0\115\0\115\0\46\0\101\0\120\0\101\0", 1, -1)
					if match then
						nw.createMeta(self.keys["ioc"], "possible_lsass_minidump")
					end
				end
			end
		end
   	end
end


fingerprint_mdmp:setCallbacks({
    ["\77\68\77\80\147\167"] = fingerprint_mdmp.magic,    -- 4d 44 4d 50 93 a7
})


return summary



-- 6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00