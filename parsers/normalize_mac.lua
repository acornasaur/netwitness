local normalizemac = nw.createParser("Normalize_MAC", "Normalize MAC address from certain logs")

--[[ The purpose of this parser is to normalize meta from the meta callback into a
properly formatted MAC address.

Parser created 2014-03-25 by Chris Ahearn
christopher.ahearn@rsa.com
--]]

normalizemac:setKeys({
    nwlanguagekey.create("eth.src", nwtypes.MAC)
})

function normalizemac:macMeta(index, mac)
    -- localize or initialize table to hold seen mac addresses
    local seenmac = self.seenmac or {}
    -- check if this mac address has been seen before
    if not seenmac[mac] then
        -- nope, now it has
        seenmac[mac] = true
        -- copy local table back to global
        self.seenmac = seenmac
        -- Convert mac to upper case
        local normal_mac = string.upper(string.gsub(mac, "-", ":"))
        -- *check if this mac has been registered before
        if not seenmac[normal_mac] then
			nw.createMeta(self.keys["eth.src"], normal_mac)
		end
    end
end

function normalizemac:sessionEnd()
    self.seenmac = nil
end

--[[ Place meta callback info here.  You may need to modify the log parser to use a different
transient meta key as TEXT.  This is because eth.dst is formatted as MAC which expects
AA:BB:CC:11:22:33 format.  The dmacaddr key below is ONLY a placeholder. -]]

normalizemac:setCallbacks({
    [nwlanguagekey.create("sourcemac")] = normalizemac.macMeta,
    [nwevents.OnSessionEnd] = normalizemac.sessionEnd,
})