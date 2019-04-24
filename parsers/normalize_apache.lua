local normalize_apache = nw.createParser("normalize_apache", "Normalize Apache Log Data")


--[[
    
    DESCRIPTION

        Normalize apache log data
        

    AUTHOR
    
    	christopher.ahearn@rsa.com 


    VERSION

		2019.04.24	-	Initial development


    DEPENDENCIES

        None

--]]


-- Write meta into the following meta key(s)
normalize_apache:setKeys({
	nwlanguagekey.create("referer",nwtypes.Text),
})

	
function normalize_apache:sessionBegin()
	devicetype = nil
end

function normalize_apache:devicetypeMeta(index,dtype)
	if dtype == 'apache' then
		devicetype = dtype
	end
end

function normalize_apache:urlMeta(index,meta)
	if dtype == 'apache' then
		nw.createMeta(self.keys["referer"], meta)
	end
end


-- declare what tokens and events we want to match
normalize_apache:setCallbacks({
    [nwevents.OnSessionBegin] = normalize_apache.sessionBegin,
    [nwlanguagekey.create("device.type", nwtypes.Text)] = normalize_apache.devicetypeMeta, 
    [nwlanguagekey.create("url", nwtypes.Text)] = normalize_apache.urlMeta,       
})