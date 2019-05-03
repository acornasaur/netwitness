local lua_citrix = nw.createParser("lua_citrix", "Identify citrix traffic")

--[[
    DESCRIPTION

        Identify citrix network traffic and register into service.  
        

    VERSION
	
        2019-05-03 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		None
        
--]]




function lua_citrix:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
	setmeta = nil
end

function lua_citrix:tokenMATCH(token, first, last)
	if first <= 32 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then	
			setmeta = 1
		end
	end
end

function lua_citrix:tokenMATCH2(token, first, last)	
	if setmeta == 1 then
		if first <= 256 then
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notcitrix) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(2598)
					--nw.logInfo("*** SERVICE 2598 ***")
					self.state.identified = true
				elseif service ~= 2598 then
					self.state.notcitrix = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end	
		end	
	end			
end

function lua_citrix:tokenMATCH3(token, first, last)	
	if first <= 32 then
		local status, error = pcall(function()
		self.state = self.state or {}
		if not (self.state.identified or self.state.notcitrix) then
			local service = nw.getAppType()
			if not service or service == 0 then
				nw.setAppType(2598)
				--nw.logInfo("*** SERVICE 2598 ***")
				self.state.identified = true
			elseif service ~= 2598 then
				self.state.notcitrix = true
			end
		end
		end)
		if not status and debugParser then
			nw.logFailure(error)
		end	
	end			
end

lua_citrix:setCallbacks({
	[nwevents.OnSessionBegin] = lua_citrix.sessionBegin,
	["\26\67\71\80\47\48\49"] = lua_citrix.tokenMATCH, -- 1a 43 47 50 2f 30 31 
	["\0\22\67\105\116\114\105\120\46\84\99\112\80\114\111\120\121\83\101\114\118\105\99\101"] = lua_citrix.tokenMATCH2, -- 00 16 43 69 74 72 69 78 2e 54 63 70 50 72 6f 78 79 53 65 72 76 69 63 65
	["\127\127\73\67\65\0"] = lua_citrix.tokenMATCH3, -- 7f 7f 49 43 41 00	
})
