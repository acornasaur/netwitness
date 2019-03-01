-- Step 1 - Create parser
local veritas_netbackup = nw.createParser("veritas_netbackup", "Identify Veritas Netbackup traffic")

--[[
    DESCRIPTION

        Identify Veritas Netbackup traffic


    VERSION
		
        2019-01-02 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    META KEYS
    
    	None
    	
   
    NOTES
    
		For all inquiries, congrats, or complaints, please contact Vernon
		
	
        
--]]

-- Step 2 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with

-- NONE HERE as we are setting service type

-- Step 4 - Do SOMETHING once your token matched


function veritas_netbackup:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function veritas_netbackup:tokenREQ(token, first, last)
	local protocol, srcPort, dstPort = nw.getTransport()
	if protocol == 6 then
		-- found BACKUP REQUEST
		local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notFT) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(1556)
					--nw.logInfo("*** SERVICE 1556 ***")
					self.state.identified = true
				elseif service ~= 1556 then
					self.state.notFT = true
				end
			end
		end)
		if not status and debugParser then
				nw.logFailure(error)
		end
	end
end

function veritas_netbackup:tokenGEO(token, first, last)
	local protocol, srcPort, dstPort = nw.getTransport()
	if protocol == 6 and dstPort == 1556 then
		current_position = last + 1
		local payload = nw.getPayload(current_position, current_position + 7)
		if payload and #payload == 8 then
			local magic = payload:uint16(3,4)
			-- check to make sure bytes 3 and 4 are 00.  
			if magic == 0 then
			-- found BACKUP REQUEST
				local status, error = pcall(function()
					self.state = self.state or {}
					if not (self.state.identified or self.state.notFT) then
						local service = nw.getAppType()
						if not service or service == 0 then
							nw.setAppType(1556)
							--nw.logInfo("*** SERVICE 1556 ***")
							self.state.identified = true
						elseif service ~= 1556 then
							self.state.notFT = true
						end
					end
				end)
				if not status and debugParser then
						nw.logFailure(error)
				end
			end
		end
	end
	if protocol == 6 and dstPort ~= 1556 then
		current_position = last + 1
		local payload = nw.getPayload(current_position, current_position + 7)
		if payload and #payload == 8 then
			local magic = payload:uint16(3,4)
			-- check to make sure bytes 3 and 4 are 00.  
			if magic == 0 then
				local status, error = pcall(function()
					self.state = self.state or {}
					if not (self.state.identified or self.state.notFT) then
						local service = nw.getAppType()
						if not service or service == 0 then
							nw.setAppType(15153)
							--nw.logInfo("*** SERVICE 15153 ***")
							self.state.identified = true
						elseif service ~= 15153 then
							self.state.notFT = true
						end
					end
				end)
				if not status and debugParser then
						nw.logFailure(error)
				end
			end
		end
	end
end

-- Step 3 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
veritas_netbackup:setCallbacks({
 	[nwevents.OnSessionBegin] = veritas_netbackup.sessionBegin,
	["\97\99\107\61\49\10\101\120\116\101\110\115\105\111\110\61"] = veritas_netbackup.tokenREQ,
	["\71\73\79\80\1\2\1\1"]  = veritas_netbackup.tokenGEO,
	["\71\73\79\80\1\2\1\0"]  = veritas_netbackup.tokenGEO,
})
