local lua_bt_beacon = nw.createParser("lua_bt_beacon", "LUA BitTorrent Beacon", "0")

--[[
    DESCRIPTION

        Parse Bittorrent beacons


    VERSION
		
        2016-04-16 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    META KEYS
    
    	None
    	
   
    NOTES
    
		None
		
	
        
--]]

-- declare the meta keys we'll be registering meta with

lua_bt_beacon:setKeys({
	nwlanguagekey.create("analysis.session"),
})


function lua_bt_beacon:tokenBEACON(token, first, last)
	local protocol = nw.getTransport()
	if protocol == 17 then
		nw.createMeta(self.keys["analysis.session"], "possible_bittorrent_beacon")
	end
end


-- declare what tokens and events we want to match
lua_bt_beacon:setCallbacks({
	["\49\58\97\100\50\58\105\100\50\48\58"] = lua_bt_beacon.tokenBEACON,  -- 64 31 3a 61 64 32 3a 69 64 32 30 3a
})
					
