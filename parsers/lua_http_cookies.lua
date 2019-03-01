-- Step 1 - Create parser
local lua_http_cookies = nw.createParser("lua_http_cookies", "Parser to identify HTTP Cookie information", 80)

--[[
    DESCRIPTION

        Parse HTTP Cookie information, such as length, number of cookies.
        

    VERSION
		
        2018-12-19 	- Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

      	HTTP Traffic
        
    
    META KEY REQUIREMENTS        
    	
    	<key description="Cookie Length" level="IndexValues" name="cookie.len" valueMax="65536" format="UInt16"/>
    	<key description="Cookie Value Count" level="IndexValues" name="cookie.val" valueMax="65536" format="UInt16"/>
    
    NOTES
    
    	Cookies should be no longer than 4093 bytes in length per common practice, however RFC2965 says there is no defined length.
    	https://www.ietf.org/rfc/rfc2965.txt
    	
 	
--]]

-- Step 2 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with
lua_http_cookies:setKeys({
	nwlanguagekey.create("analysis.service", nwtypes.Text),
	nwlanguagekey.create("cookie.len", nwtypes.UInt16),
	nwlanguagekey.create("cookie.val", nwtypes.UInt16),
})

-- Step 4 - Do SOMETHING once your token matched
function lua_http_cookies:tokenCookie(token, first, last)
	-- set position to byte match
	current_position = last + 1
	local payload = nw.getPayload(current_position, current_position + 5000) -- only getting payload that i need
	local mydelim = payload:find("\13\10", 1, -1)
	if mydelim then
		if mydelim >= 4093 then
			nw.createMeta(self.keys["analysis.service"], "http_long_cookie")
		end
		local mycookie = payload:tostring(1, mydelim -1)
		if mycookie then
			local mycookielen = #mycookie
			if mycookielen then
				nw.createMeta(self.keys["cookie.len"], mycookielen)
			end

			local t = {}
			local i = 0
			while true do
				i = string.find(mycookie, ";", i + 1)
				if i == nil then 
					break
				end
				table.insert(t, i)
			end
			local valfind = #t + 1
			if valfind ~= nil then
				nw.createMeta(self.keys["cookie.val"], valfind)
			end
		end
	else nw.createMeta(self.keys["analysis.service"], "http_long_cookie")
	
	end
end


-- Step 3 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
lua_http_cookies:setCallbacks({
	["^Cookie: "] = lua_http_cookies.tokenCookie,
})





















