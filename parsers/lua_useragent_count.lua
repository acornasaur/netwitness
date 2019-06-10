local lua_useragent_count = nw.createParser("lua_useragent_count", "Count unique root.host meta in a given session.")

--[[
    DESCRIPTION

        Count the number user-agents (client) in a session.


    VERSION
		
        2019-06-08 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        <key description="Client Count" level="IndexValues" name="client.count" valueMax="65537" format="UInt16"/>
      
--]]

-- Write meta into the following meta key(s)
lua_useragent_count:setKeys({
	nwlanguagekey.create("client.count",nwtypes.UInt16),  
})

function setContains(set, key)
	return set[key] ~= nil
end

function addToTable(key, value) 
	key[value] = "true"
end

function lua_useragent_count:sessionBegin()
	-- reset parser_state for the new session
	mytable = nil
	mytable = {}
	count = 0
end

function lua_useragent_count:clientMeta(index, meta)
	local client = meta
	if setContains(mytable, client) then 
		return 
	else addToTable(mytable, client) 
	end
end
	
function lua_useragent_count:sessionEnd()
	-- Count them all up
	for i,j in pairs(mytable) do 
		count = count + 1 
	end
	if count > 0 then
		nw.createMeta(self.keys["client.count"], count)
	end
end
	


-- declare what tokens and events we want to match
lua_useragent_count:setCallbacks({
    [nwevents.OnSessionBegin] = lua_useragent_count.sessionBegin,
    [nwlanguagekey.create("client")] = lua_useragent_count.clientMeta,   
    [nwevents.OnSessionEnd] = lua_useragent_count.sessionEnd,         
})