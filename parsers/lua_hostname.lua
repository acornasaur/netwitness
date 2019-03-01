local lua_hostname = nw.createParser("lua_hostname", "Extract hostname and domain from FQDN host.src meta")

--[[
    
    DESCRIPTION

        Extract hostname and domain from FQDN host.src meta from FireEye Web MPS logs
        

    AUTHOR
    
    	christopher.ahearn@rsa.com 


    VERSION
	
		2015-10-30		Adjusted else condition 
		2015-10-27		Added destination host and destination domain
		2015-10-26(a)	Changed meta keys to write to.  Also added domain
		2015-10-26		Initial development


    DEPENDENCIES

        None
        
    
    EXAMPLE
    
    	shost = "wn-oh15al3hu229.ne.us.bank-dns.com" 
    	Just extract "wn-oh15al3hu229"

--]]

-- Write meta into the following meta key(s)
lua_hostname:setKeys({
	nwlanguagekey.create("shost",nwtypes.Text), 
	nwlanguagekey.create("sdomain",nwtypes.Text), 
	nwlanguagekey.create("dhost",nwtypes.Text), 
	nwlanguagekey.create("ddomain",nwtypes.Text), 
})

-- function to reset a global variable that will be used throughout the parser
function lua_hostname:sessionBegin()
	devicetype = nil
end


-- function for host.src callback 
function lua_hostname:srcMeta(index, meta)
	-- read the meta value from meta callback key
	-- find the first dot position
	local pos = string.find(meta, "%.")
	-- if we found the dot
	if pos then
		local myhost = string.sub(meta, 1, pos - 1)
		local mydomain = string.sub(meta, pos + 1, -1)
		-- if we have myhost, then you win...now write meta
		if myhost then
			-- write meta
			nw.createMeta(self.keys["shost"], myhost)
			-- OPTIONAL DEBUG to log output to syslog. Helpful for testing
			--nw.logInfo("*** SHOST: " .. myhost .. " ***")
		end
		if mydomain then
			-- write meta
			nw.createMeta(self.keys["sdomain"], mydomain)
			-- OPTIONAL DEBUG to log output to syslog. Helpful for testing
			--nw.logInfo("*** SDOMAIN: " .. mydomain .. " ***")
		end
	else
		-- if it didn't have a dot, then it must not have been an FQDN
		local myhost = meta
		if myhost then
			nw.createMeta(self.keys["shost"], myhost)
			-- OPTIONAL DEBUG to log output to syslog. Helpful for testing
			--nw.logInfo("*** ELSE SHOST: " .. myhost .. " ***")
		end
	end
end

-- function for host.dst callback 
function lua_hostname:dstMeta(index, meta)
	-- read the meta value from meta callback key
	-- find the first dot position
	local pos = string.find(meta, "%.")
	-- if we found the dot
	if pos then
		local myhost = string.sub(meta, 1, pos - 1)
		local mydomain = string.sub(meta, pos + 1, -1)
		-- if we have myhost, then you win...now write meta
		if myhost then
			-- write meta
			nw.createMeta(self.keys["dhost"], myhost)
			-- OPTIONAL DEBUG to log output to syslog. Helpful for testing
			--nw.logInfo("*** DHOST: " .. myhost .. " ***")
		end
		if mydomain then
			-- write meta
			nw.createMeta(self.keys["ddomain"], mydomain)
			-- OPTIONAL DEBUG to log output to syslog. Helpful for testing
			--nw.logInfo("*** DDOMAIN: " .. mydomain .. " ***")
		end
	else
		-- if it didn't have a dot, then it must not have been an FQDN
		local myhost = meta
		if myhost then
			nw.createMeta(self.keys["dhost"], myhost)
			-- OPTIONAL DEBUG to log output to syslog. Helpful for testing
			--nw.logInfo("*** ELSE DHOST: " .. myhost .. " ***")
		end
	end
end

-- declare what tokens and events we want to match
lua_hostname:setCallbacks({
    [nwlanguagekey.create("host.src")] = lua_hostname.srcMeta, 
    [nwlanguagekey.create("host.dst")] = lua_hostname.dstMeta,           
})