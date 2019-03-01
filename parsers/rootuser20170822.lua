-- Step 1 - Create parser
local lua_normalize_user = nw.createParser("lua_normalize_user", "Normalize User.dst meta")

--[[
    DESCRIPTION

        Normalize user.dst meta


    VERSION

        Initial development - 2015-12-02
        2016-09-02 - added LDAP:// as a string find and read up to the location
        2016-09-08 - had to modify the matchslash find to '\\\\' as it was incorrectly set
		2017-08-22 - account for user dst meta that has both a slash "\" and an at "@"
		
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        
    
    META
        
    	Custom meta key called root.user will be needed.
    	
    	    
    SAMPLE
    
   'ldap://cnbjsgc101.cn.myrealm.mydomain.com cn=users,dc=cn,dc=myrealm,dc=mydomain,dc=com/summerzzhang'
    mymeta = "LDAP://172.16.1.34 OU=Stamford,DC=customerdomain,DC=net/Brower\, Dan (Stamford) "
    
    bob@abc.com
	abc\bob
	ldap://......./bob
	Bob\...........@abc.com
	bob

    
    
--]]

-- Step 2 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with
lua_normalize_user:setKeys({
 	nwlanguagekey.create("root.user", nwtypes.Text),
})

-- Step 4 - Do SOMETHING once your token matched
function findLast(haystack, needle)
   local i=haystack:match(".*"..needle.."()")
   if i==nil then return nil else return i-1 end
end

priority = nil

function lua_normalize_user:tokenFIND(token, mymeta)
    local matchldap = string.find(mymeta, "ldap://")
    if matchldap then
    	local last = findLast(mymeta, "/")
    	local username = string.lower(string.sub(mymeta, last + 1, -1))
    	if username then
           nw.createMeta(self.keys["root.user"], username)
           --nw.logInfo("*** ROOTUSER_LOWER_LDAP " .. username .. " ***")
        end
    end
    
    local matchslash = string.find(mymeta, "\\\\")
    if matchslash then
    	--nw.logInfo("*** FOUND SLASH SLASH***")
        local username = string.lower(string.sub(mymeta, matchslash + 1))
        if username then
           	nw.createMeta(self.keys["root.user"], username)
           	--nw.logInfo("*** ROOTUSER_SLASH_SLASH " .. username .. " ***")
        end
    end
    
    local matchat = string.find(mymeta, "@")
    if matchat then
    	--nw.logInfo("*** FOUND AT ***")
        local usertemp = string.lower(string.sub(mymeta, 1, matchat - 1))
        if usertemp then
        	local findslash = string.find(usertemp, "\\")
        	if findslash then
        		local username = string.lower(string.sub(usertemp, 1, findslash - 1))
        		if username then
        			nw.createMeta(self.keys["root.user"], username)
        		end
        	else
        		nw.createMeta(self.keys["root.user"], usertemp)
        		--nw.logInfo("*** ROOTUSER_AT " .. usertemp .. " ***")
        	end
        end
    end  
    
    local matchLDAP = string.find(mymeta, "LDAP://")
    if matchLDAP then
    	--nw.logInfo("*** MATCH LDAP ***")
    	local last = findLast(mymeta, "/")
    	local nrawuser = string.lower(string.sub(mymeta, last + 1, -1))
    	local rawuser = string.gsub(nrawuser, "\\,", ",")
    	if rawuser then
    		--nw.logInfo("*** RAWUSER: " .. rawuser .. " ***")
    		local location = string.find(rawuser, " %(")
    		if location then
    			local username = string.sub(rawuser, 1, location - 1)
    			--nw.logInfo("*** USERNAME_WITHOUT_LOCATION: " .. username .. " ***")
    			nw.createMeta(self.keys["root.user"], username)
   				--nw.logInfo("*** ROOTUSER1: " .. username .. " ***")
    		else
    			local username = rawuser
    			--nw.logInfo("*** USERNAME_ELSE: " .. username .. " ***")
    			nw.createMeta(self.keys["root.user"], username)
   				--nw.logInfo("*** ROOTUSER2: " .. username .. " ***")
    		end
    		priority = 1
    	end
    end
            
 	local matchslash = string.find(mymeta, "\\")
 	if priority == 1 then
    	return
    else
		if matchslash then
			--nw.logInfo("*** FOUND SLASH ***")
			local username = string.lower(string.sub(mymeta, matchslash + 1))
			if username then
				local searchat = string.find(username, "@")
				if searchat then
					return
				else
					nw.createMeta(self.keys["root.user"], username)
				end
			end
		end
	end
    
    if not matchldap then
   		if not matchslash then
    		if not matchat then
    			if not matchslash then
					if not matchLDAP then
						local username = string.lower(mymeta)
						if username then
							nw.createMeta(self.keys["root.user"], username)
							--nw.logInfo("*** ROOTUSER_NOMATCH: " .. username .. " ***")
						end
					end
				end
        	end
    	end
	end
end


-- Step 3 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
lua_normalize_user:setCallbacks({
	[nwlanguagekey.create("user.dst")] = lua_normalize_user.tokenFIND,
})
