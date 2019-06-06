local lua_ocsp = nw.createParser("lua_ocsp", "Identify ocsp traffic")

--[[
    DESCRIPTION

        Identify ocsp network traffic and register into service.  
        

    VERSION
	
        2019-05-11 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		None
        
--]]

lua_ocsp:setKeys({
	nwlanguagekey.create("analysis.service",nwtypes.Text),
})

function lua_ocsp:tokenMATCH(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 then
		current_position = last + 1
		local payload = nw.getPayload(current_position, current_position + 12)
		if payload then
			local check = payload:find("\48\130", 1, -1)
			if check then
				nw.createMeta(self.keys["analysis.service"], "ocsp_check")			
			end
		end	
	end		
end

lua_ocsp:setCallbacks({
	["\13\10\13\10\48\130"] = lua_ocsp.tokenMATCH, -- 0d 0a 0d 0a 30 82
})
