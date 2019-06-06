local lua_domain_depth = nw.createParser("lua_domain_depth", "Count the dots and get the domain depth from alias.host meta")

--[[
    DESCRIPTION

        Count the dots in meta from alias.host to identify domain depth.


    VERSION
		
        2019-06-06 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        <key description="Domain Depth" level="IndexValues" name="domain.depth" valueMax="65537" format="UInt16"/>
      
--]]

lua_domain_depth:setKeys({
    nwlanguagekey.create("domain.depth", nwtypes.UInt16),
})


---checks if a string represents an ip address
-- @return true or false
function isIpAddress(ip)
 	if not ip then return false end
	local a,b,c,d=ip:match("^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$")
 	a=tonumber(a)
	b=tonumber(b)
 	c=tonumber(c)
 	d=tonumber(d)
 	if not a or not b or not c or not d then return false end
 	if a<0 or 255<a then return false end
 	if b<0 or 255<b then return false end
 	if c<0 or 255<c then return false end
 	if d<0 or 255<d then return false end
 	return true
end


function lua_domain_depth:hostMeta(index, host)
	if host then
	
		local app = nw.getAppType() 
		if app == 137 or app == 138 or app == 139 then
			--nw.logInfo("*** APPTYPE: " .. app .. " ***")
			return
		else
	
			local ipcheck = isIpAddress(host)
			if ipcheck == true then
				return
			else
				local numDots = 0
				for dot in string.gmatch(host, "%.") do
					numDots = numDots + 1
				end
		
				local count = numDots -- this gives us the total number of entries in the table
			
				if count == 0 then
					return
				else
					nw.createMeta(self.keys["domain.depth"], count)
					--nw.logInfo("*** DOMAIN DEPTH: " .. count .. " ***")
				end		
			end		
		end	
	end
end

lua_domain_depth:setCallbacks({
    [nwevents.OnSessionBegin] = lua_domain_depth.sessionBegin,
    [nwlanguagekey.create("alias.host")] = lua_domain_depth.hostMeta,
})
