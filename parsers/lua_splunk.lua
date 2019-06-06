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
	if first <= 4096 then
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
end

function lua_splunk:tokenMATCH2(token, first, last)
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
	["\45\45\115\112\108\117\110\107\45\99\111\111\107\101\100\45\109\111\100\101\45\118\51\45\45"] = lua_splunk.tokenMATCH, -- 2d 2d 73 70 6c 75 6e 6b 2d 63 6f 6f 6b 65 64 2d 6d 6f 64 65 2d 76 33 2d 2d
	["--splunk-cooked-mode-v3--"] = lua_splunk.tokenMATCH,
	["\95\115\50\115\95\99\97\112\97\98\105\108\105\116\105\101\115\0\0\0\0\20\97\99\107\61\49"] = lua_splunk.tokenMATCH, -- _s2s_capabilitiesack=1 -- 5f 73 32 73 5f 63 61 70 61 62 69 6c 69 74 69 65 73 00 00 00 00 14 61 63 6b 3d 31
	["\95\114\97\119\0\0\0\0\182\70\111\114\119\97\114\100\101\114\73\110\102\111\32\98\117\105\108\100"] = lua_splunk.tokenMATCH,
	["\95\114\97\119\0\0\0\0\173\70\111\114\119\97\114\100\101\114\73\110\102\111\32\98\117\105\108\100"] = lua_splunk.tokenMATCH,
	["\95\114\97\119\0\0\0\0\172\70\111\114\119\97\114\100\101\114\73\110\102\111\32\98\117\105\108\100"] = lua_splunk.tokenMATCH,
	["\95\114\97\119\0\0\0\0\170\70\111\114\119\97\114\100\101\114\73\110\102\111"] = lua_splunk.tokenMATCH,	
	["\35\35\35\32\83\69\82\73\65\76\73\90\69\68\32\84\73\77\69\90\79\78\69\32\70\79\82\77\65\84"] = lua_splunk.tokenMATCH, -- 23 23 23 20 53 45 52 49 41 4c 49 5a 45 44 20 54 49 4d 45 5a 4f 4e 45 20 46 4f 52 4d 41 54 -- ### SERIALIZED TIMEZONE FORMAT
	["\252\3\255\132\1\177\253\176\189\253\183\188\200\157\1\234"] = lua_splunk.tokenMATCH,
	["\10\66\10\70\10\36\10\254\1\29\115\111\117\114\99\101\58\58"] = lua_splunk.tokenMATCH,
	["sourcetype::splunkd\6"] = lua_splunk.tokenMATCH,
	["\95\115\50\115\95\99\111\110\116\114\111\108\95\109\115\103\0"] = lua_splunk.tokenMATCH,
	["\254\3\29\115\111\117\114\99\101\58\58"] = lua_splunk.tokenMATCH,
	["\2\4\5\95\112\97\116\104"] = lua_splunk.tokenMATCH2,
	["\3\4\5\95\112\97\116\104"] = lua_splunk.tokenMATCH2,
	["\1\77\115\111\117\114\99\101\58\58"] = lua_splunk.tokenMATCH2,
})

--5f 72 61 77 00 00 00 00 b6 46 6f 72 77 61 72 64 65 72 49 6e 66 6f