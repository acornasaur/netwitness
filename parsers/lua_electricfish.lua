local lua_electricfish = nw.createParser("lua_electricfish", "Identify electricfish traffic")

--[[
    DESCRIPTION

        Identify electricfish network traffic and register into ioc.  
        

    VERSION
	
        2019-05-12 - Initial development 
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		https://www.us-cert.gov/ncas/analysis-reports/AR19-129A
        
--]]

lua_electricfish:setKeys({
    nwlanguagekey.create("ioc",nwtypes.Text),
})


function lua_electricfish:tokenMATCH(token, first, last)
	current_position = last + 1
	local payload = nw.getPayload(current_position, current_position + 20)
	if payload then
		local match = payload:find("\0\0\4\0\0\0", 1, -1)
		if match then
			nw.createMeta(self.keys["ioc"], "possible_electricfish")
		end
	end
end

lua_electricfish:setCallbacks({
	[nwevents.OnSessionBegin] = lua_electricfish.sessionBegin,
	["\97\97\97\97\98\98\98\98\99\99\99\99\100\100\100\100\0\0\0\0\0\0\0\0"] = lua_electricfish.tokenMATCH, -- 61 61 61 61 62 62 62 62 63 63 63 63 64 64 64 64 00 00 00 00 00 00 00 00 
})

