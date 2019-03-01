-- Step 1 - Create parser
local vsphere_replication = nw.createParser("vsphere_replication", "Identify VMWare vSphere Replication")

--[[
    DESCRIPTION

        Identify VMWare vSphere Replication


    VERSION
		
        2018-01-31 - Initial development
        
       
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


function vsphere_replication:sessionBegin()
	-- reset parser_state for the new session
	self.state = nil
end

function vsphere_replication:tokenREQ(token, first, last)
	local protocol, srcPort, dstPort = nw.getTransport()
	if protocol == 6 and dstPort == 31031 then
		-- found REPLICATION REQUEST
		local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notFT) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(31031)
					--nw.logInfo("*** SERVICE 31031 ***")
					self.state.identified = true
				elseif service ~= 31031 then
					self.state.notFT = true
				end
			end
		end)
		if not status and debugParser then
				nw.logFailure(error)
		end
	end
end



-- Step 3 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
vsphere_replication:setCallbacks({
 	[nwevents.OnSessionBegin] = vsphere_replication.sessionBegin,
	["\048\048\145\134\104\025\003\003\020\000\000\000\005\000\000\000"] = vsphere_replication.tokenREQ,
})







