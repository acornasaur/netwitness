local luaPorts = nw.createParser("lua_ports", "Normalize Source and Destination Ports")


--[[
    
    DESCRIPTION

        Normalize the meta for Source and Destination ports for packet and log sources
        

    AUTHOR
    
    	christopher.ahearn@rsa.com 


    VERSION
		
		2015.06.01	Changed to write to ip.srcport and ip.dstport instead
		2015.03.23	Initial development


    DEPENDENCIES

        None

--]]


-- Write meta into the following meta key(s)
luaPorts:setKeys({
	nwlanguagekey.create("ip.srcport",nwtypes.UInt16),
	nwlanguagekey.create("ip.dstport",nwtypes.UInt16),
})

function luaPorts:srcMeta(index,portsrc)
	-- read the value from transient meta
	if portsrc then
		nw.createMeta(self.keys["ip.srcport"], portsrc)
	end
end

function luaPorts:dstMeta(index,portdst)
	-- read the value from transient meta
	if portdst then
		nw.createMeta(self.keys["ip.dstport"], portdst)
	end
end


-- declare what tokens and events we want to match
luaPorts:setCallbacks({
    [nwlanguagekey.create("tcp.srcport", nwtypes.UInt16)] = luaPorts.srcMeta,
    [nwlanguagekey.create("udp.srcport", nwtypes.UInt16)] = luaPorts.srcMeta,
    [nwlanguagekey.create("tcp.dstport", nwtypes.UInt16)] = luaPorts.dstMeta,
    [nwlanguagekey.create("udp.dstport", nwtypes.UInt16)] = luaPorts.dstMeta,            
})