local lua_splunk = nw.createParser("lua_splunk", "Identify splunk traffic")

--[[
    DESCRIPTION

        Identify splunk network traffic and register into service.  
        

    VERSION
	
        2019-01-08 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES

        
--]]




function lua_splunk:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function lua_splunk:tokenMATCH(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 then
		local status, error = pcall(function()
		self.state = self.state or {}
		if not (self.state.identified or self.state.notsplunk) then
			local service = nw.getAppType()
			if not service or service == 0 then
				nw.setAppType(9997)
				--nw.logInfo("*** SERVICE 9997 ***")
				self.state.identified = true
			elseif service ~= 9997 then
				self.state.notsplunk = true
			end
		end
		end)
		if not status and debugParser then
			nw.logFailure(error)
		end		
	end				
end

lua_splunk:setCallbacks({
	[nwevents.OnSessionBegin] = lua_splunk.sessionBegin,
	["\45\45\115\112\108\117\110\107\45\99\111\111\107\101\100\45\109\111\100\101\45\118\51\45\45"] = lua_splunk.tokenMATCH, -- 0 2d 2d 73 70 6c 75 6e 6b 2d 63 6f 6f 6b 65 64 2d 6d 6f 64 65 2d 76 33 2d 2d
})


