local dns_fun = nw.createParser("dns_fun_parser", "dns_fun parser in lua", 53)

-- declare the meta keys we'll be registering meta with
dns_fun:setKeys({
	nwlanguagekey.create("alert")
})

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function dns_fun:sessionBegin(token, first, last)
	local resStream = nwsession.getResponseStream()
	local payload = nw.getPayload(resStream,1,512)
	if payload then
		local string_temp = payload:tostring(1, -1)
		local hexpay = string.tohex(string_temp)
		nw.logInfo(hexpay)
	end	
	
	local length = payload:len()
	if length then
		nw.logInfo("*** DNS PAYLOAD LENGTH: " .. length .. " ***")
	end
	
	local dnsid = payload:uint16(1)
	if dnsid then
		local hexdnsid = bit.tohex(dnsid, 4)
		nw.logInfo("*** DNS ID: " .. hexdnsid .. " ***")
	end

	local flags = payload:uint16(3)
	if flags then
		local hexflags = bit.tohex(flags, 4)
		nw.logInfo("*** DNS FLAGS: " .. hexflags .. " ***")
	end
	
	local questioncount = payload:uint16(5)
	if questioncount then
		local hexquestioncount = bit.tohex(questioncount, 4)
		nw.logInfo("*** DNS QUESTION COUNT " .. hexquestioncount .. " ***")
	end
	
	local answercount = payload:uint16(7)
	if answercount then
		local hexanswercount = bit.tohex(answercount, 4)
		nw.logInfo("*** DNS ANSWER COUNT " .. hexanswercount .. " ***")
	end
	
	current_position = 13
	local questiondelim = payload:find("\000", current_position, -1)
	if questiondelim then
		local questionend = questiondelim - 1
		local question = payload:tostring(current_position + 1, questionend)
		nw.logInfo("*** DNS QUESTION: " .. question .. " ***")
	end
	
	current_position = questiondelim + 1
	local querytype = payload:uint16(current_position)
	if querytype then
		local hexquerytype = bit.tohex(querytype, 4)
		nw.logInfo("*** DNS QUERYTYPE: " .. hexquerytype .. " ***")
	end
	
	
	
end

-- declare what tokens and events we want to match
dns_fun:setCallbacks({
	[nwevents.OnSessionBegin] = dns_fun.sessionBegin,
})


--if bit.band(flag, i) == i then