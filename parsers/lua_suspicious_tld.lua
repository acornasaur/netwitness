local lua_suspicious_tld = nw.createParser("suspicious_tld", "Identify a suspicious TLD in DNS traffic.", "53")

--[[
    DESCRIPTION

        Identify a suspicious Top Level Domain in DNS traffic.


    VERSION
		
        2019-05-22 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        
    META KEYS
    
    	
   
    NOTES
    
		tld = 'fdfd0137235843554df6faffff5dca06b0'
		
	
        
--]]


-- These are the meta keys that we will write meta into
lua_suspicious_tld:setKeys({
    nwlanguagekey.create("ioc", nwtypes.Text),
})

function lua_suspicious_tld:sessionBegin()
	-- reset parser_state for the new session
	count = 0
end

-- This is our function.  What we want to do when we match a token...or in this case, the 
-- meta callback.
function lua_suspicious_tld:tldMeta(index, meta)
	if #meta >= 16 then
		for x in string.gmatch(meta, "[^/]+") do
			local dir = x	
			local var = nil
			--get the length of directory meta
			for i = 1, #dir do 
				--get individual characters
				local c = dir:sub(i,i)   
				--check if each character is a hex byte                                                                           
				if not string.match(c, "%x") then                                                                   
					var = 1                                                                                             
				end                                                                                                 
			end
			if var == 1 then
				return
			else
				nw.createMeta(self.keys["ioc"], "suspicious_tld")
				count = count + 1
				if count == 10 then
					nw.createMeta(self.keys["ioc"], "possible_dns_tunneling")
				end
			end

		end
	end
end

lua_suspicious_tld:setCallbacks({
	[nwevents.OnSessionBegin] = lua_suspicious_tld.sessionBegin,
    [nwlanguagekey.create("tld")] = lua_suspicious_tld.tldMeta,  -- this is the meta callback key
})