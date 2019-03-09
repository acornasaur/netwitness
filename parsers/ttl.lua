local ttl = nw.createParser("ttl", "Time to Live")

--[[
    DESCRIPTION

       Extract TTL for both request and response streams
        

    VERSION
		
		2017-02-01 - Initial version came from experimental passive OS fingerprint parser
        2019-03-09 - Modified to extract TTL of both request and response streams
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        This will use nwpacket quite a bit because the data is in the packet headers, not
        the session payload.
        
    META KEYS
    
    	<key description="TTL Request"  level="IndexValues" name="ttl.req"  format="UInt8" valueMax="300" defaultAction="Closed"/>
		<key description="TTL Response"  level="IndexValues" name="ttl.resp"  format="UInt8" valueMax="300" defaultAction="Closed"/>
	
--]]

-- declare the meta keys we'll be registering meta with
ttl:setKeys({
	nwlanguagekey.create("ttl.req",nwtypes.UInt8),
	nwlanguagekey.create("ttl.resp",nwtypes.UInt8),
})



function ttl:sessionBegin()

	local requestStream = nwsession.getRequestStream()
	local responseStream = nwsession.getResponseStream()
	
	if requestStream then		
		local firstpreq = nwstream.getFirstPacket(requestStream)

		local payload = nwpacket.tostring(firstpreq,1,32)
		if payload then
			-- Find the upper layer protocol type for IP (0x800) and move forward 1 byte into it.
			local ipheaderpos = payload:find("\008\000", 1, -1)
			if ipheaderpos then
				local iphdr = ipheaderpos + 2
				-- Find the time to live (TTL) value in the IP header
				-- 8th byte offset from 0 in the IP header
				-- 8bit field
				if iphdr ~= nil then
					local ttl = nwpacket.byte(firstpreq, iphdr + 8)
					if ttl then
						local pdisplay = tonumber(ttl)
						if pdisplay <=255 then
							--nw.logInfo("REQUEST TTL:  " .. pdisplay)
							nw.createMeta(self.keys["ttl.req"], pdisplay)
						end
					end
				end	
			end
		end
	end
	
	if responseStream then		
		local firstpresp = nwstream.getFirstPacket(responseStream)

		local payload = nwpacket.tostring(firstpresp,1,32)
		if payload then
			-- Find the upper layer protocol type for IP (0x800) and move forward 1 byte into it.
			local ipheaderpos = payload:find("\008\000", 1, -1)
			if ipheaderpos then
				local iphdr = ipheaderpos + 2
				-- Find the time to live (TTL) value in the IP header
				-- 8th byte offset from 0 in the IP header
				-- 8bit field
				if iphdr ~= nil then
					local ttl = nwpacket.byte(firstpresp, iphdr + 8)
					if ttl then
						local pdisplay = tonumber(ttl)
						if pdisplay <=255 then
							--nw.logInfo("RESPONSE TTL:  " .. pdisplay)
							nw.createMeta(self.keys["ttl.resp"], pdisplay)
						end
					end
				end	
			end
		end
	end
end	



ttl:setCallbacks({
    [nwevents.OnSessionBegin] = ttl.sessionBegin,
})
