local lua_sesamestreet = nw.createParser("lua_sesamestreet", "Count unique hosts, tld's and sld's in a given session.")

--[[
    DESCRIPTION

        Count unique hosts, tld's and sld's in a given session.
        

    VERSION
	
        2019-05-21 - Initial development 
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES
    
		A little humor on the subject
		https://www.youtube.com/watch?v=InZInH0RlL4
		
	META KEYS
	
		<key description="Alias Host Count" level="IndexValues" name="alias.host.count" valueMax="65537" format="UInt16"/>
		<key description="Root Host Count" level="IndexValues" name="root.host.count" valueMax="65537" format="UInt16"/>
		<key description="TLD Count" level="IndexValues" name="tld.count" valueMax="65537" format="UInt16"/>
		<key description="SLD Count" level="IndexValues" name="sld.count" valueMax="65537" format="UInt16"/>
        
--]]

-- Write meta into the following meta key(s)
lua_sesamestreet:setKeys({ 
	nwlanguagekey.create("alias.host.count",nwtypes.UInt16),  
	nwlanguagekey.create("tld.count",nwtypes.UInt16), 
	nwlanguagekey.create("sld.count",nwtypes.UInt16),  
	nwlanguagekey.create("root.host.count",nwtypes.UInt16),   
})

function setContains(set, key)
	return set[key] ~= nil
end

function addToTable(key, value) 
	key[value] = "true"
end

function lua_sesamestreet:sessionBegin()
	-- reset parser_state for the new session
	mytable_ah = nil
	mytable_ah = {}
	count_ah = 0
	
	mytable_rh = nil
	mytable_rh = {}
	count_rh = 0
	
	mytable_tld = nil
	mytable_tld = {}
	count_tld = 0
	
	mytable_sld = nil
	mytable_sld = {}
	count_sld = 0
end

function lua_sesamestreet:aliashostMeta(index, ameta)
	local ahost = ameta
	if setContains(mytable_ah, ahost) then 
		return 
	else addToTable(mytable_ah, ahost) 
	--nw.logInfo("*** AHOST: " .. ahost .. " ***")
	end
end

function lua_sesamestreet:roothostMeta(index, rmeta)
	local rhost = rmeta
	if setContains(mytable_rh, rhost) then 
		return 
	else addToTable(mytable_rh, rhost) 
	--nw.logInfo("*** RHOST: " .. rhost .. " ***")
	end
end

function lua_sesamestreet:tldMeta(index, tmeta)
	local mytld = tmeta
	if setContains(mytable_tld, mytld) then 
		return 
	else addToTable(mytable_tld, mytld) 
	end
end

function lua_sesamestreet:sldMeta(index, smeta)
	local mysld = smeta
	if setContains(mytable_sld, mysld) then 
		return 
	else addToTable(mytable_sld, mysld) 
	end
end
	
function lua_sesamestreet:sessionEnd()
	-- Count them all up
	for a,b in pairs(mytable_ah) do 
		count_ah = count_ah + 1 
	end
	--nw.logInfo("*** ALIAS HOST COUNT: " .. count_ah .. " ***")
	if count_ah > 0 then
		nw.createMeta(self.keys["alias.host.count"], count_ah)
	end
	
	for c,d in pairs(mytable_rh) do 
		count_rh = count_rh + 1 
	end
	--nw.logInfo("*** ROOT HOST COUNT: " .. count_rh .. " ***")
	if count_rh > 0 then
		nw.createMeta(self.keys["root.host.count"], count_rh)
	end
	
	for e,f in pairs(mytable_tld) do 
		count_tld = count_tld + 1 
	end
	--nw.logInfo("*** TLD COUNT: " .. count_tld .. " ***")
	if count_tld > 0 then
		nw.createMeta(self.keys["tld.count"], count_tld)
	end

	for g,h in pairs(mytable_sld) do 
		count_sld = count_sld + 1 
	end
	--nw.logInfo("*** SLD COUNT: " .. count_sld .. " ***")
	if count_sld > 0 then
		nw.createMeta(self.keys["sld.count"], count_sld)
	end		
end
	


-- declare what tokens and events we want to match
lua_sesamestreet:setCallbacks({
    [nwevents.OnSessionBegin] = lua_sesamestreet.sessionBegin,
    [nwlanguagekey.create("alias.host")] = lua_sesamestreet.aliashostMeta,   
    [nwlanguagekey.create("root.host")] = lua_sesamestreet.roothostMeta,   
    [nwlanguagekey.create("tld")] = lua_sesamestreet.tldMeta,   
    [nwlanguagekey.create("sld")] = lua_sesamestreet.sldMeta,   
    [nwevents.OnSessionEnd] = lua_sesamestreet.sessionEnd,         
})



lua_sesamestreet:setCallbacks({
	[nwlanguagekey.create("device.type")] = lua_policy_change.deviceMeta,  -- this is the meta callback key
	[nwlanguagekey.create("index")] = lua_policy_change.policyMeta,  -- this is the meta callback key
})
