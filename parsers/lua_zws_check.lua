local lua_zws_check = nw.createParser("lua_zws_check", "Check alias.host meta for zero-width spaces")

--[[
    DESCRIPTION

        Check alias.host meta for zero-width spaces


    VERSION
		
        2019-01-24 - Initial development
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

       None
        
    META KEYS
    
    	
   
    NOTES
    
    https://thehackernews.com/2019/01/phishing-zero-width-spaces.html?m=1
    http://www.amp-what.com/unicode/search/zero%20width
        
--]]


-- These are the meta keys that we will write meta into
lua_zws_check:setKeys({
    nwlanguagekey.create("ioc", nwtypes.Text),
})

local zws = ({

	["\226\128\139"] = true, -- &#8203;  &NegativeMediumSpac  zero width space
	["\226\128\140"] = true, -- &#8204;  &zwnj;  zero width non-joiner
	["\226\128\141"] = true, -- &#8205;  &zwj;  zero width joiner
	["\239\187\191"] = true, -- &#65279;  zero width no-break space
	["\239\188\144"] = true, -- &#65296;  fullwidth digit zero	
	
})

-- This is our function.  What we want to do when we match a token...or in this case, the 
-- filename meta callback.
function lua_zws_check:hostMeta(index, meta)
	if meta then
		for i,j in pairs(zws) do
			local check = string.find(meta, i)
			if check then
				--nw.logInfo("*** BAD HOSTNAME CHECK: " .. meta .. " ***")
				nw.createMeta(self.keys["ioc"], "hostname_zero-width_space")
				break
			end
		end	
	end
end

lua_zws_check:setCallbacks({
    [nwlanguagekey.create("alias.host")] = lua_zws_check.hostMeta,  -- this is the meta callback key
})

