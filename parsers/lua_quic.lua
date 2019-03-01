local lua_quic = nw.createParser("lua_quic", "QUIC Protocol Identification")

--[[
  5.1.  QUIC Common Packet Header

   All QUIC packets on the wire begin with a common header sized between
   2 and 21 bytes.  The wire format for the common header is as follows:


     0        1        2        3        4            8
+--------+--------+--------+--------+--------+---    ---+
| Public |    Connection ID (0, 8, 32, or 64)    ...    | ->
|Flags(8)|      (variable length)                       |
+--------+--------+--------+--------+--------+---    ---+

     9       10       11        12
+--------+--------+--------+--------+
|      Quic Version (32)            | ->
|         (optional)                |
+--------+--------+--------+--------+

    13      14       15        16        17       18       19       20
+--------+--------+--------+--------+--------+--------+--------+--------+
|         Sequence Number (8, 16, 32, or 48)          |Private | FEC (8)|
|                         (variable length)           |Flags(8)|  (opt) |
+--------+--------+--------+--------+--------+--------+--------+--------+


	
--]]

-- declare the meta keys we'll be registering meta with
lua_quic:setKeys({
	nwlanguagekey.create("alias.host",nwtypes.Text),
})



-- Bytes as Nibbles
-- 128	64	32	16	|	8	4	2	1 
--	8	4	2	1	|	8	4	2	1



function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function string.fromhex(str)
	str = str:gsub('00','')
    local x = {}
    for y in str:gmatch('(..)') do
		if (tonumber(y,16) >= 32 and tonumber(y,16) <= 126) then
			x[#x+1] = string.char( tonumber(y, 16) )
		elseif (tonumber(y,16) == 10 or tonumber(y,16) == 13) then
			x[#x+1] = ''
		else
			return ''
		end
    end
    return table.concat( x )
end


function lua_quic:sessionBegin()
	self.state = nil
	padnumval = nil
	sninumval = nil
	
	local protocol = nw.getTransport()
	if protocol == 17 then
		local requestStream = nwsession.getRequestStream()
		local responseStream = nwsession.getResponseStream()

		if requestStream then		
			local packet = nwsession.getFirstPacket(requestStream)
			local size,psize = nwpacket.getSize(packet)
			local payload = nwpacket.getPayload(packet)
			if payload then
				-- Check the first byte
				--nw.logInfo("*** PAYLOAD FOUND ***")
				local quicpf = payload:find("\13", 1,1)
				if quicpf then
					--nw.logInfo("*** PAYLOAD: " .. string.tohex(payload) .. " ***")
					local versionf,versionl = payload:find("Q0", 2,-1)
					if versionl then
						local version = payload:tostring(versionf, versionf + 3)
						--nw.logInfo("*** VERSION: " .. version .. " ***")
						
						current_position = versionl + 1
						local hellof,hellol = payload:find("CHLO",current_position, -1)
						if hellol then
							--nw.logInfo("*** HELLO FOUND ***")
							local status, error = pcall(function()
							self.state = self.state or {}
							if not (self.state.identified or self.state.notQK) then
								local service = nw.getAppType()
								if not service or service == 0 then
									nw.setAppType(8148)
									--nw.logInfo("*** SERVICE 8148 ***")
									self.state.identified = true
								elseif service ~= 8148 then
									self.state.notQK = true
								end
							end
							end)
							if not status and debugParser then
								nw.logFailure(error)
							end
							current_position = hellol + 1
							local tagnum = payload:uint16(current_position, current_position + 1, true)
							if tagnum then
								--nw.logInfo("*** TAGNUM: " .. tagnum .. " ***")
								local tagcount = tagnum
								current_position = current_position + 4
								local endOfField = payload:find("\45\45\45\45", current_position)
								if endOfField then
									-- read up to the space
									local mylist = payload:tostring(current_position, endOfField -1)
									-- make sure the read succeeded
									if mylist then
										-- this should give us the field of all the tagvals
										-- now build a table to find and hold the positions of all the delimiters
										found, foundpos = {}, 0
										repeat
											loopagain = false
											foundpos = string.find(mylist, "\0\0", foundpos)
											if foundpos then
												foundpos = foundpos + 1
												table.insert(found, foundpos)
												if #found <= tagnum then
													loopagain = true
												end
											end
										until loopagain == false
										local count = #found
										start = 1
										for i,v in ipairs(found) do
											local pad = nil
											--nw.logInfo("*** " .. i .. ":" .. v .. " ***")
											local tagval = string.sub(mylist, start, v)
											local taghex = string.tohex(tagval)
											--nw.logInfo("*** TAGVAL: " .. tagval .. " ***")
											--nw.logInfo("*** TAGHEX: " .. taghex .. " ***")
											if string.find(taghex, "50414400") then
												local padhex = string.sub(taghex, 9, 12)
												if padhex then
													local byte1 = string.sub(padhex, 1,2)
													local byte2 = string.sub(padhex, 3,4)
													local padnum = byte2 .. byte1
													padnumval = tonumber(padnum, 16)
													--nw.logInfo("*** PADNUM: " .. padnumval .. " ***")
												end
											end
											if string.find(taghex, "534E4900") then
												local snihex = string.sub(taghex, 9, 12)
												if snihex then
													local byte1 = string.sub(snihex, 1,2)
													local byte2 = string.sub(snihex, 3,4)
													local sninum = byte2 .. byte1
													sninumval = tonumber(sninum, 16)
													--nw.logInfo("*** SNINUM: " .. sninumval .. " ***")
												end
											end
											start = v + 1																					
										end
										if sninumval ~= nil then
											if padnumval ~= nil then
												local snilen = sninumval - padnumval -1
												current_position = endOfField + padnumval
												local hosttemp = payload:tostring(current_position, current_position + snilen)
												if hosttemp then
													nw.createMeta(self.keys["alias.host"], hosttemp)
													--nw.logInfo("*** HOSTNAME: " .. hosttemp .. " ***")	
												end
											end
										end
									end
								end										
							end
						end
					end
				end			
			end
		
		end
	end		
end	

--local packet = payload:getPacketPayload()

lua_quic:setCallbacks({
    [nwevents.OnSessionBegin] = lua_quic.sessionBegin,
})
