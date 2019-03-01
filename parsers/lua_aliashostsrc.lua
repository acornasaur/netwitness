local lua_aliashostsrc = nw.createParser("lua_aliashostsrc", "Move meta into host.src and host.dst for testing")

-- Write meta into the following meta key(s)
lua_aliashostsrc:setKeys({
	nwlanguagekey.create("host.src",nwtypes.Text), 
	nwlanguagekey.create("host.dst",nwtypes.Text),   
})


function lua_aliashostsrc:srcMeta(index, meta)
	nw.createMeta(self.keys["host.src"], meta)
end

function lua_aliashostsrc:dstMeta(index, meta)
	nw.createMeta(self.keys["host.dst"], meta)
end

-- declare what tokens and events we want to match
lua_aliashostsrc:setCallbacks({
    [nwlanguagekey.create("alias.host")] = lua_aliashostsrc.srcMeta,  
    [nwlanguagekey.create("referer.host")] = lua_aliashostsrc.dstMeta,           
})