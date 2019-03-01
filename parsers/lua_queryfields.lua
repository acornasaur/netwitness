local lua_queryfields = nw.createParser("lua_queryfields", "Extract individual query fields from the query fields and values", "80")

--[[
    DESCRIPTION

        Extract individual query fields from the queryfields


    VERSION
		
        2018-02-18 - Initial development
        2018-02-25 - Added query values
        2018-02-27 - bug fixes
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

       None
        
    META KEYS
    
    	<key description="Query Field" level="IndexValues" name="query.field" valueMax="1000000" format="Text"/>
    	<key description="Query Values" level="IndexValues" name="query.values" valueMax="1000000" format="Text"/>
    	
   
    NOTES
    
		meta = 'cmp=291&memberid=110705906&lyrisid=42240055&cleanedparams=1'
		
		query.field = cmp
		query.field = memberid
		query.field = lyrsid
		query.field = cleanedparams
		
		query.value = cmp=291
		query.value = memberid=110705906
		query.value = lyrisid=42240055
		query.value = cleanedparams=1
		
	
        
--]]


-- These are the meta keys that we will write meta into
lua_queryfields:setKeys({
    nwlanguagekey.create("query.field", nwtypes.Text),
    nwlanguagekey.create("query.value", nwtypes.Text),
})

-- This is our function.  What we want to do when we match a token...or in this case, the 
-- query meta callback.
function lua_queryfields:queryMeta(index, meta)
	if meta then
		-- Find all the '=' in the query meta
		found, foundpos = {}, 0
		repeat
			loopagain = false
			foundpos = string.find(meta, "=", foundpos)
			if foundpos then
				foundpos = foundpos + 1
				table.insert(found, foundpos)
				loopagain = true
			end
		until loopagain == false
		
		if #found >= 1 then
			-- Now that we have all the '=' locations, time to search
			-- loop through the positions and extract query fields along the way
			start = 1
			for i,j in ipairs(found) do
				local myfield = string.sub(meta, start, j - 2)
				if myfield then
					nw.createMeta(self.keys["query.field"], myfield)
					local delim = string.find(meta, "%&", j + 1)
					if delim then
						start = delim + 1
					else
						return
					end
				end
			end
	
			-- Great, now you got all the fields, but maybe we can get the fields with values
	
			foundval, foundvalpos = {}, 0
			repeat
				loopagain = false
				foundvalpos = string.find(meta, "%&", foundvalpos)
				if foundvalpos then
					foundvalpos = foundvalpos + 1
					table.insert(foundval, foundvalpos)
					loopagain = true
				end
			until loopagain == false
			
			if #foundval >= 1 then
			
				table.insert(foundval, -1)
		
				startval = 0
	
				for p,finishval in ipairs(foundval) do
					if p == #foundval then
						finishval = -1
					else
						finishval = finishval - 2
					end
					local myfieldval = string.sub(meta, startval + 1, finishval)
					if myfieldval then
						nw.createMeta(self.keys["query.value"], myfieldval)
						startval = finishval + 1
					end
				end	
			end
		end
	end
end

lua_queryfields:setCallbacks({
    [nwlanguagekey.create("query")] = lua_queryfields.queryMeta,  -- this is the meta callback key
})

