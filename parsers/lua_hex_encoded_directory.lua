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
-- directory meta callback.
function lua_hexdir:directoryMeta(index, meta)
	local dir = meta
	--check if directory is 16 or 32 bytes long (account for slashes)
	if #dir == 16 or #dir == 17 or #dir == 18 or #dir == 32 or #dir == 33 or #dir == 34 then
		-- check if the directory contains slash at the first and last positions
		local slash1 = string.find(dir, "/", 1,1)
		if slash1 then
			--strip off leading slash
			dir = string.sub(dir, 2, -1)
		end	
		local slash2 = string.find(dir, "/", -1,-1)
		if slash2 then
			--strip off trailing slash
			dir = string.sub(dir, 1, -2)
		end	
		
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

lua_hexdir:setCallbacks({
    [nwlanguagekey.create("directory")] = lua_hexdir.directoryMeta,  -- this is the meta callback key
})