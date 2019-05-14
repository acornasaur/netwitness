local lua_hexdir = nw.createParser("Hex Dir", "Identify a hex-encoded directory.")

--[[
    DESCRIPTION

        Identify a hex-encoded directory


    VERSION
		
        2019-05-14 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        
    META KEYS
    
    	
   
    NOTES
    
		None
		
	
        
--]]


-- These are the meta keys that we will write meta into
lua_hexdir:setKeys({
    nwlanguagekey.create("ioc", nwtypes.Text),
})

-- This is our function.  What we want to do when we match a token...or in this case, the 
-- meta callback.
function lua_hexdir:directoryMeta(index, meta)
	if #meta >= 16 then
		for x in string.gmatch(meta, "[^/]+") do
			local dir = x	
			if #dir == 16 or #dir == 32 then
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
					nw.createMeta(self.keys["ioc"], "hex_encoded_directory")
				end
			end
		end
	end
end

lua_hexdir:setCallbacks({
    [nwlanguagekey.create("directory")] = lua_hexdir.directoryMeta,  -- this is the meta callback key
})