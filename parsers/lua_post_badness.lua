-- Step 1 - Create parser
local lua_post_badness = nw.createParser("lua_post_badness", "Identify suspicious HTTP POSTs", "80")

--[[
    DESCRIPTION

        Identify suspicious HTTP POSTs


    VERSION
		
        2017-12-19 - Initial development
        2017-12-29 - Added function to attempt command extraction
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    META KEYS
    
    	None
    	
   
    NOTES
    
		None
		
	
        
--]]

-- Step 2 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with
lua_post_badness:setKeys({
	nwlanguagekey.create("ioc", nwtypes.Text),
	nwlanguagekey.create("command", nwtypes.Text),
})

-- Step 4 - Do SOMETHING once your token matched
function lua_post_badness:sessionBegin()
	-- reset global variables
	foundpost = nil
end

function lua_post_badness:tokenPOST(token, first, last)
	if nw.isRequestStream() then
		foundpost = 1
	end
end

function lua_post_badness:tokenJAVALang(token, first, last)
	if foundpost == 1 then
		if nw.isRequestStream() then
			-- set position to byte match
			current_position = last + 1
			local payload = nw.getPayload(current_position, current_position + 4096)
			local find_powershell = payload:find("powershell", 1, -1)
			if find_powershell then
				nw.createMeta(self.keys["ioc"], "java_post_powershell")
				local cmdfind = payload:find("uq", find_powershell, -1)
				if cmdfind then
					local foundcmd = payload:tostring(find_powershell, cmdfind -4)
					if foundcmd then
						local normalmsg = string.gsub(foundcmd, "\x74\x00", "\x20")
						if normalmsg then
							nw.createMeta(self.keys["command"], normalmsg)
						end
					end
				end
				return
			end
			local find_wget = payload:find("wget", 1, -1)
			if find_wget then
				nw.createMeta(self.keys["ioc"], "java_post_wget")
				local cmdfind = payload:find("uq", find_wget, -1)
				if cmdfind then
					local foundcmd = payload:tostring(find_wget, cmdfind -4)
					if foundcmd then
						local normalmsg = string.gsub(foundcmd, "\x74\x00", "\x20")
						if normalmsg then
							nw.createMeta(self.keys["command"], normalmsg)
						end
					end
				end
				return
			end
			local find_curl = payload:find("curl", 1, -1)
			if find_curl then
				nw.createMeta(self.keys["ioc"], "java_post_curl")
				local cmdfind = payload:find("uq", find_curl, -1)
				if cmdfind then
					local foundcmd = payload:tostring(find_curl, cmdfind -4)
					if foundcmd then
						local normalmsg = string.gsub(foundcmd, "\x74\x00", "\x20")
						if normalmsg then
							nw.createMeta(self.keys["command"], normalmsg)
						end
					end
				end
				return
			end
			local find_cmd = payload:find("cmd", 1, -1)
			if find_cmd then
				nw.createMeta(self.keys["ioc"], "java_post_cmd")
				local cmdfind = payload:find("uq", find_cmd, -1)
				if cmdfind then
					local foundcmd = payload:tostring(find_cmd, cmdfind -4)
					if foundcmd then
						--nw.logInfo("*** FOUND CMD: " .. foundcmd .. " ***")
						local normalmsg = string.gsub(string.gsub(string.gsub(foundcmd, "\x74\x00", "\x20"),"\x02", ""),"cmd.exet../ct.", "cmd.exe /c ")
						if normalmsg then
							--nw.logInfo("*** NORMAL MSG: " .. normalmsg .. " ***")
							nw.createMeta(self.keys["command"], normalmsg)
						end
					end
				end
				return
			end
			local find_bash = payload:find("bash", 1, -1)
			if find_bash then
				nw.createMeta(self.keys["ioc"], "java_post_bash")
				local cmdfind = payload:find("uq", find_bash, -1)
				if cmdfind then
					local foundcmd = payload:tostring(find_bash, cmdfind -4)
					if foundcmd then
						local normalmsg = string.gsub(foundcmd, "\x74\x00", "\x20")
						if normalmsg then
							nw.createMeta(self.keys["command"], normalmsg)
						end
					end
				end
				return
			end
		end
	end		
end

function lua_post_badness:tokenCMDString(token, first, last)
	if foundpost == 1 then
		if nw.isRequestStream() then
			-- set position to byte match
			current_position = last + 1
			--nw.logInfo("*** POST COMMAND STRING TOKEN MATCH ***")
			local payload = nw.getPayload(current_position, current_position + 1024)
			local findstringf, findstringl = payload:find("<string>", 1, -1)
			if findstringl then
				current_position = findstringl + 1
				local foundendf, foundendl = payload:find("</string>\10", current_position, -1)
				if foundendf then
					--nw.logInfo("*** FOUND END ***")
					local foundcmd = payload:tostring(current_position, foundendf -1)
					if foundcmd then
						--nw.logInfo("*** FOUND CMD ***")
						--nw.logInfo("*** " ..  foundcmd .. " ***")
						local findstring = string.find(foundcmd, "</string><string>")
						if findstring then
							--nw.logInfo("*** FOUND STRING ***")
							local mycmd = string.gsub(foundcmd, "</string><string>", " ")
							if mycmd then
								--nw.logInfo("*** MY COMMAND " .. mycmd .. " ***")
								nw.createMeta(self.keys["command"], mycmd)
							end
						else
							nw.createMeta(self.keys["command"], foundcmd)
						end
					end
				end
			end
		end
	end
end

function lua_post_badness:tokenSTRINGMod(token, first, last)
	if foundpost == 1 then
		if nw.isRequestStream() then
			-- set position to byte match
			current_position = first + 8
			local payload = nw.getPayload(current_position, current_position + 1024)
			local findendstringf, findendstringl = payload:find("</string>", 1, -1)
			if findendstringf then
				local foundcmd = payload:tostring(1, findendstringf -1)
				if foundcmd then
					if #foundcmd > 10 then
						local findstring = string.find(foundcmd, "</string><string>")
						if findstring then
							local mycmd = string.gsub(foundcmd, "</string><string>", " ")
							if mycmd then
								nw.createMeta(self.keys["command"], mycmd)
							end
						else
							nw.createMeta(self.keys["command"], foundcmd)
						end
					end
				end
			end
		end
	end
end

function lua_post_badness:tokenARRAY(token, first, last)
	if foundpost == 1 then
		if nw.isRequestStream() then
			-- set position to byte match
			current_position = last + 1
			--nw.logInfo("*** ARRAY TOKEN MATCH ***")
			local payload = nw.getPayload(current_position, current_position + 8096)
			local startoffieldf, startoffield = payload:find("<string>", 1 -1)
			local endoffield = payload:find("</array>", 1, -1)
			if startoffield and endoffield then
				local mylist = payload:tostring(startoffield +1, endoffield -1)
				if mylist then
					found, foundpos = {}, 0
					cmd = {}
					repeat
						loopagain = false
						foundpos = string.find(mylist, "</string>", foundpos)
						if foundpos then
							foundpos = foundpos +1
							table.insert(found, foundpos)
							loopagain = true
						end
					until loopagain == false
					start = 1
					for i,v in ipairs(found) do
						local mycmd = string.sub(mylist, start, v -1)
						table.insert(cmd, mycmd)
						start = string.find(mylist, "<string>", v, -1)
					end
					if #cmd >= 1 then
						local mycommand = string.gsub(table.concat(cmd, " "),"< <string>", " ")
						if mycommand then
							nw.createMeta(self.keys["command"], mycommand)
							--nw.logInfo("*** COMMAND: " .. mycommand .. " ***")
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
lua_post_badness:setCallbacks({
	[nwevents.OnSessionBegin] = lua_post_badness.sessionBegin,
	["^POST "] = lua_post_badness.tokenPOST, -- the carat ^ indicates beginning of line
	["java.lang.String"] = lua_post_badness.tokenJAVALang,
	["\60\99\111\109\109\97\110\100\62\10"] = lua_post_badness.tokenCMDString,
	["<string>cmd"] = lua_post_badness.tokenSTRINGMod,
	["<string>powershell"] = lua_post_badness.tokenSTRINGMod,
	["<string>curl"] = lua_post_badness.tokenSTRINGMod,
	["<string>wget"] = lua_post_badness.tokenSTRINGMod,
	["<string>bash"] = lua_post_badness.tokenSTRINGMod,
	["<string>/bin/bash"] = lua_post_badness.tokenSTRINGMod,
	["<array\32class=\34java.lang.String\34"] = lua_post_badness.tokenARRAY,
})
