local hostlen = nw.createParser("Host_Length", "Find the length of domain from alias.host")

--[[
Parser Returns the following Meta

 	<key description="Hostname Length" level="IndexValues" name="alias.host.len" valueMax="100000" format="UInt16"/>
      	
]]--

hostlen:setKeys({
    nwlanguagekey.create("alias.host.len",nwtypes.UInt16)
})

function hostlen:hostMeta(index, host)
	local hostLength = string.len(host)
	if hostLength then
		nw.createMeta(self.keys["alias.host.len"], hostLength)
	end
end

hostlen:setCallbacks({
    [nwlanguagekey.create("alias.host")] = hostlen.hostMeta,
})