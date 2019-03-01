-- Step 1 - Create parser
local lua_geoip_extras = nw.createParser("lua_geoip_extras", "lua_geoip_extras Parser")

--[[
COMMENTS GO HERE
--]]

-- Since we are using an external module, we declare it here.  
-- This must be in the parsers directory
local nwll = require('nwll')


-- Step 3 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with
lua_geoip_extras:setKeys({
	nwlanguagekey.create("asn.src", nwtypes.Text),
	nwlanguagekey.create("asn.dst", nwtypes.Text),
	nwlanguagekey.create("continent.src", nwtypes.Text),
	nwlanguagekey.create("continent.dst", nwtypes.Text),
	nwlanguagekey.create("org.orig", nwtypes.Text),
	nwlanguagekey.create("country.orig", nwtypes.Text),
})

-- Step 4 - Do SOMETHING once your token matched

-- Get ASN and Continent information from ip.src and ip.dst
function lua_geoip_extras:OnHostSrc(index, src)
	local asnsrc = self:geoipLookup(src, "autonomous_system_number")
	local continentsrc = self:geoipLookup(src, "continent", "names", "en")
	
	if asnsrc then
		--nw.logInfo("*** ASN SOURCE: AS" .. asnsrc .. " ***")
		nw.createMeta(self.keys["asn.src"], "AS" .. asnsrc)
	end
	if continentsrc then
		--nw.logInfo("*** CONTINENT SOURCE: " .. continentsrc .. " ***")
		nw.createMeta(self.keys["continent.src"], continentsrc )
	end
	
end

function lua_geoip_extras:OnHostDst(index, dst)
	local asndst = self:geoipLookup(dst, "autonomous_system_number")
	local continentdst = self:geoipLookup(dst, "continent", "names", "en")
	
	if asndst then
		--nw.logInfo("*** ASN DESTINATION: AS" .. asndst .. " ***")
		nw.createMeta(self.keys["asn.dst"], "AS" .. asndst)
	end
	if continentdst then
		--nw.logInfo("*** CONTINENT DESTINATION " .. continentdst.. " ***")
		nw.createMeta(self.keys["continent.dst"], continentdst)
	end
	
end

-- Get Country and Organization from orig_ip and ip.orig (new with UDM) 
-- orig_ip is text formatted therefore, must determine host type first
-- ip.orig is new with UDM and is formatted as IPv4
function lua_geoip_extras:OrigSrc(index, meta)
 	local host, key = nwll.determineHostType(meta)
 	--nw.logInfo("*** HOST TYPE HOST: " .. host .. " KEY: " .. key .. " ***")
	if host and key and key == "alias.ip" then
		local country = self:geoipLookup(host, "country", "names", "en") 
		local org = self:geoipLookup(host, "organization")
		if country then
			nw.createMeta(self.keys["country.orig"], country )
		end
		if org then
			nw.createMeta(self.keys["org.orig"], org )
		end
	end
end

function lua_geoip_extras:IPOrig(index, meta)
	local country = self:geoipLookup(meta, "country", "names", "en") 
	local org = self:geoipLookup(meta, "organization")
	if country then
		nw.createMeta(self.keys["country.orig"], country )
	end
	if org then
		nw.createMeta(self.keys["org.orig"], org )
	end
end

-- Step 2 - Define tokens that get you close to what you want
-- declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
lua_geoip_extras:setCallbacks({
	[nwlanguagekey.create("ip.src", nwtypes.IPv4)] = lua_geoip_extras.OnHostSrc,
	[nwlanguagekey.create("ip.dst", nwtypes.IPv4)] = lua_geoip_extras.OnHostDst,
	[nwlanguagekey.create("orig_ip", nwtypes.Text)] = lua_geoip_extras.OrigSrc,	
	[nwlanguagekey.create("ip.orig", nwtypes.IPv4)] = lua_geoip_extras.IPOrig,
})

