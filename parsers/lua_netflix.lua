local luanetflix = nw.createParser("lua_netflix_detect", "Detect Netflix traffic on a network")

--[[

    DESCRIPTION

        Detect Netflix streaming traffic

    VERSION

        2014.12.29  christopher.ahearn@rsa.com - Initial development
		2014.12.29.1  christopher.ahearn@rsa.com - Added some video streaming fragment detection

    DEPENDENCIES

        none
        
    TODO
    	Re-write the video fragment section to look for matches within range of other matches
	
--]]

-- declare the meta keys we'll be registering meta with
luanetflix:setKeys({
	nwlanguagekey.create("alert"),
})

function luanetflix:StreamBegin()
	-- reset parser_state for the new session
	self.Path = nil
	rmatch = nil
	cmatch = nil
	smatch = nil
	fragmoof = nil
	fragmfhd = nil
	fragtraf = nil
	isnetflix = nil
	response = nwstream.isResponse
end

function luanetflix:tokenRESPONSE(token, first, last)
	if response then
		rmatch = 1
	end
end

function luanetflix:tokenCONTENT(token, first, last)
	if rmatch == 1 then
		cmatch = 1
	end	
end

function luanetflix:tokenSTREAM(token, first, last)
	if cmatch == 1 then
		smatch = 1
	end	
end

function luanetflix:tokenLIB(token, first, last)
	if smatch == 1 then
		nw.createMeta(self.keys["alert"], "netflix_streaming")
		isnetflix = 1
	end	
end

function luanetflix:tokenFRAGMOOF(token, first, last)
	if cmatch == 1 then
		fragmoof = 1
	end	
end

function luanetflix:tokenFRAGMFHD(token, first, last)
	if fragmoof == 1 then
		fragmfhd = 1
	end	
end

function luanetflix:tokenFRAGTRAF(token, first, last)
	if fragmfhd == 1 then
		fragtraf = 1
	end	
end

function luanetflix:tokenFRAGTFHD(token, first, last)
	if fragtraf == 1 then
		if isnetflix == 1 then
			return
		else
			nw.createMeta(self.keys["alert"], "video_streaming_fragment")
		end	
	end
end

-- declare what tokens and events we want to match
luanetflix:setCallbacks({
	[nwevents.OnStreamBegin] = luanetflix.StreamBegin,
	["^HTTP/1.2 200"] = luanetflix.tokenRESPONSE,
	["^HTTP/1.1 200"] = luanetflix.tokenRESPONSE,
	["^HTTP/1.0 200"] = luanetflix.tokenRESPONSE,
	["^HTTP/1.2 206"] = luanetflix.tokenRESPONSE,
	["^HTTP/1.1 206"] = luanetflix.tokenRESPONSE,
	["^HTTP/1.0 206"] = luanetflix.tokenRESPONSE,
	["^Content-Type: application/octet-stream"] = luanetflix.tokenCONTENT,
	["NetflixPiffStrm"] = luanetflix.tokenSTREAM,
	["Netflix Media Library Version"] = luanetflix.tokenLIB,
	["moof"] = luanetflix.tokenFRAGMOOF,	
	["mfhd"] = luanetflix.tokenFRAGMFHD,
	["traf"] = luanetflix.tokenFRAGTRAF,
	["tfhd"] = luanetflix.tokenFRAGTFHD,
})