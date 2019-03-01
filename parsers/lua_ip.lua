local lua_ip = nw.createParser("lua_ip", "Copy all ip addresses into one common key")


--[[
    
    DESCRIPTION

        Copy all ip addresses into one common key
        

    AUTHOR
    
    	christopher.ahearn@rsa.com 


    VERSION

		2015.12.03	-	Initial development


    DEPENDENCIES

        None

--]]


-- Write meta into the following meta key(s)
lua_ip:setKeys({
	nwlanguagekey.create("ip",nwtypes.IPv4),
})


function lua_ip:ipMeta(index,ipmeta)
	-- read the value from transient meta
	if ipmeta then
		nw.createMeta(self.keys["ip"], ipmeta)
	end
end


-- declare what tokens and events we want to match
lua_ip:setCallbacks({
    [nwlanguagekey.create("alias.ip", nwtypes.IPv4)] = lua_ip.ipMeta, 
    [nwlanguagekey.create("ip.addr", nwtypes.IPv4)] = lua_ip.ipMeta,         
    [nwlanguagekey.create("ip.src", nwtypes.IPv4)] = lua_ip.ipMeta,
    [nwlanguagekey.create("ip.dst", nwtypes.IPv4)] = lua_ip.ipMeta,           
})