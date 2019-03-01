local lua_filename_check = nw.createParser("lua_filename_check", "Check EXE filenames for all digits")

--[[
    DESCRIPTION

        Check EXE filenames for all digits"


    VERSION
		
        2018-09-11 - Initial development
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

       None
        
    META KEYS
    
    	
   
    NOTES

		
	
        
--]]


-- These are the meta keys that we will write meta into
lua_filename_check:setKeys({
    nwlanguagekey.create("ioc", nwtypes.Text),
})

-- This is our function.  What we want to do when we match a token...or in this case, the 
-- filename meta callback.
function lua_filename_check:filenameMeta(index, meta)
	local exef,exel = string.find(meta, ".exe", 1, -1)
	if exef then
		local analyze = string.sub(meta, 1, exef - 1)
		local num = tonumber(analyze)
		if num == nil then
			return
		else
			nw.createMeta(self.keys["ioc"], "exe_filename_all_numbers")
		end
	end	
end

lua_filename_check:setCallbacks({
    [nwlanguagekey.create("filename")] = lua_filename_check.filenameMeta,  -- this is the meta callback key
    [nwlanguagekey.create("attachment")] = lua_filename_check.filenameMeta,
})

