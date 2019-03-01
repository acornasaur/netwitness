local lua_b64_inline_image = nw.createParser("lua_b64_inline_image", "Identify inlined images encoded in base64", "80")

--[[
    DESCRIPTION

        Identify inlined images encoded in base64


    VERSION
		
        2017-02-22 - Initial development
        
       
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
lua_b64_inline_image:setKeys({
	nwlanguagekey.create("ir.general"),
})

function lua_b64_inline_image:tokenINLINE(token, first, last)
	if first then
		nw.createMeta(self.keys["ir.general"], "inline_b64_image")
	end
end


-- declare what tokens and events we want to match
lua_b64_inline_image:setCallbacks({
	["data:image/jpg;base64,"] = lua_b64_inline_image.tokenINLINE, 
	["data:image/png;base64,"] = lua_b64_inline_image.tokenINLINE, 
	["data:image/gif;base64,"] = lua_b64_inline_image.tokenINLINE, 
	["data:image/jpeg;base64,"] = lua_b64_inline_image.tokenINLINE, 
})
					
