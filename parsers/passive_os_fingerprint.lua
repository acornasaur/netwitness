local passive_os_fingerprint = nw.createParser("passive_os_fingerprint", "Passive OS Fingerprint")

--[[
    DESCRIPTION

        ***** THIS PARSER IS EXPERIMENTAL *****
        
        Parser used to extract juicy bits from the first SYN packet of a TCP session in 
        an effort to provide enough data for passive OS fingerprinting.
        
        The idea came from using p0f.  See p0f for more details.
        
        See the following site for a breakdown of the signature format.
        https://blog.cloudflare.com/introducing-the-p0f-bpf-compiler/
        
        Signature
		As mentioned, the p0f SYN signature is a colon-separated string with the following parts:
		
			IP version:	the first field carries the IP version. Allowed values are 4 and 6.
			Initial TTL: assuming that realistically a packet will not jump through more than 35 hops, we can specify an initial TTL ittl (usual values are 255, 128, 64 and 32) and check if the packet's TTL is in the range (ittl, ittl - 35).
			IP options length: length of IP options. Although it's not that common to see options in the IP header (and so 0 is the typical value you would see in a signature), the standard defines a variable length field before the IP payload where options can be specified. A * value is allowed too, which means "not specified".
			MSS: maximum segment size specified in the TCP options. Can be a constant or *.
			Window Size: window size specified in the TCP header. It can be a expressed as:
				a constant c, like 8192
				a multiple of the MSS, in the c*mss format
				a multiple of a constant, in the %c format
				any value, as *
			Window Scale: window scale specified during the three way handshake. Can be a constant or *.
			TCP options layout: list of TCP options in the order they are seen in a TCP packet.
			Quirks: comma separated list of unusual (e.g. ACK number set in a non ACK packet) or incorrect (e.g. malformed TCP options) characteristics of a packet.
			Payload class: TCP payload size. Can be 0 (no data), + (1 or more bytes of data) or *.
		
		TCP Options format
			The following common TCP options are recognised:
			nop: no-operation
			mss: maximum segment size
			ws: window scaling
			sok: selective ACK permitted
			sack: selective ACK
			ts: timestamp
			eol+x: end of options followed by x bytes of padding
		
		Quirks
			p0f describes a number of quirks:
			df: don't fragment bit is set in the IP header
			id+: df bit is set and IP identification field is non zero
			id-: df bit is not set and IP identification is zero
			ecn: explicit congestion flag is set
			0+: reserved ("must be zero") field in IP header is not actually zero
			flow: flow label in IPv6 header is non-zero
			seq-: sequence number is zero
			ack+: ACK field is non-zero but ACK flag is not set
			ack-: ACK field is zero but ACK flag is set
			uptr+: URG field is non-zero but URG flag not set
			urgf+: URG flag is set
			pushf+: PUSH flag is set
			ts1-: timestamp 1 is zero
			ts2+: timestamp 2 is non-zero in a SYN packet
			opt+: non-zero data in options segment
			exws: excessive window scaling factor (window scale greater than 14)
			linux: match a packet sent from the Linux network stack (IP.id field equal to TCP.ts1 xor TCP.seq_num). Note that this quirk is not part of the original p0f signature format; we decided to add it since we found it useful.
			bad: malformed TCP options
        

    VERSION
		
		2017-02-01 - Initial version
        2017-02-08 - Adding additional variables and changing the signature format for 
        			 use by latest p0f fingerprint file as a feed (i hope)
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        This will use nwpacket quite a bit because the data is in the packet headers, not
        the session payload.
        
	
--]]

-- declare the meta keys we'll be registering meta with
passive_os_fingerprint:setKeys({
	nwlanguagekey.create("ttl",nwtypes.UInt8),
	nwlanguagekey.create("dont.fragment",nwtypes.UInt8),
	nwlanguagekey.create("tcp.window_size", nwtypes.UInt16),
	nwlanguagekey.create("max.segment_size", nwtypes.UInt16),
	nwlanguagekey.create("win.scale", nwtypes.UInt16),
	nwlanguagekey.create("os.fingerprint", nwtypes.Text),
})


-- TCP Header Length can be found at the 12th byte offset from 0 in the TCP header.
-- It is a 4bit field in the high order nibble
-- minimum value 5 (5x4=20bytes)   maximum value 15 (15x4=60bytes)
-- Purpose is to identify TCP header length to identify any TCP Options.
-- Then, move to where the TCP Options start
-- Default TCP Header size is 20 bytes.  Anything more than that and you have TCP Options.

-- Bytes as Nibbles
-- 128	64	32	16	|	8	4	2	1 
--	8	4	2	1	|	8	4	2	1


local tcpheaderlennibval = ({       
	[80] = 5, -- a value of 5 * 4 = 20 bytes, which means NO TCP Options
	[96] = 6,
	[112] = 7,
	[128] = 8,
	[144] = 9,
	[160] = 10,
	[176] = 11,
	[192] = 12,
	[208] = 13,
	[224] = 14,
	[240] = 15
})


function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function passive_os_fingerprint:sessionBegin()

	iphdr = nil
	tcphdr = nil

	local requestStream = nwsession.getRequestStream()
	local responseStream = nwsession.getResponseStream()
	local protocol = nw.getTransport()
	
	
	if requestStream then		
		local firstp = nwsession.getFirstPacket(requestStream)

		local payload = nwpacket.tostring(firstp,1,32)
		if payload then
			-- Find the upper layer protocol type for IP (0x800) and move forward 1 byte into it.
			local ipheaderpos = payload:find("\008\000", 1, -1)
			if ipheaderpos then
				iphdr = ipheaderpos + 2
			end			
		end

		-- Find the time to live (TTL) value in the IP header
		-- 8th byte offset from 0 in the IP header
		-- 8bit field
		if iphdr ~= nil then
			
			-- check that the IP version is 4 and header length is 5
			-- 0x45 equals decimal 69
			local verlen = nwpacket.byte(firstp, iphdr + 0)
			if verlen == 69 then
				ipversion = "4"
				ipoptionslen = 0
				-- this gives us the start of ip payload, which would be protocol
				-- The payload begins at the 20th byte offset from 0 in the IP Header
				-- Since I only care about TCP, the variable name will be 'tcphdr' even
				-- though it could be any protocol really.
				tcphdr = iphdr + 20		
				local ttl = nwpacket.byte(firstp, iphdr + 8)
				if ttl then
					local pdisplay = tonumber(ttl)
					if pdisplay <=255 then
						--nw.logInfo("TTL:  " .. pdisplay)
						nw.createMeta(self.keys["ttl"], pdisplay)
						timetolive = ttl
					end
				end
				
				-- Find the IP Identification field and check if it is zero or not zero.
				-- The IP Identification field is 16bits and can bein found at the 4th 
				-- byte offset from 0 in the IP header
				local ipid = nwpacket.uint16(firstp, iphdr + 4)
				if ipid == 0 then
					ipidval = 0
				else
					ipidval = 1
				end
				
				-- Find the value of Don't Fragment flag in the IP Header	
				-- 6th byte offset from 0 in the IP header. 
				-- 3bits of the high order nibble 
				-- Not sure yet if there is value in registering this as meta, but we shall see.
				local fragflag = nwpacket.byte(firstp, iphdr + 6)
				if fragflag then
					--nw.logInfo("DON'T FRAGMENT: " .. fragflag)
					if fragflag == 64 then
						local df = 1
						--nw.logInfo("DF: " .. df)
						nw.createMeta(self.keys["dont.fragment"], df)
						frag = df
						ipfrag = "df"
						if df == 1 then
							if ipidval == 1 then
								quirks = "df,id+"
							else
								quirks = "df"
							end
						end
					else
						local df = 0
						--nw.logInfo("DF: " .. df)
						nw.createMeta(self.keys["dont.fragment"], df)
						frag = df
					end					
				end

				-- Check we are in a TCP session
				if protocol == 6 then
				-- Check the 'tcphdr' is not nil.  Then, check the first packet has only 
				-- the SYN flag.  This would be the beginning of the 3-way handshake.
				-- TCP flags are found at the 13th byte offset from 0 in the TCP header
					if tcphdr ~= nil then
						local firstsyn = nwpacket.byte(firstp,tcphdr + 13)
						if firstsyn == 2 or firstsyn == 194 then
							-- Find the length of the initial SYN packet
							local packet_size = nwpacket.getSize(firstp)
							--nw.logInfo("PACKET SIZE: " .. packet_size)
							local synp_size = packet_size - (iphdr - 1)
							synpacketsize = synp_size
							
							-- Find TCP Header Length, which is found at the 12th byte offset 
							-- from 0 in the TCP header
							local tcpheaderlen = nwpacket.uint8(firstp,tcphdr + 12)
							if tcpheaderlen >= 96 then
								headerlen =  (tcpheaderlennibval[tcpheaderlen] * 4)
								if headerlen then
									--nw.logInfo("TCP HEADER LENGTH: " .. headerlen)
								end		
							end
							
							-- Find TCP Window Size, which is found at the 14th byte offset 
							-- from 0 in the TCP header
							local tcpwinsize = nwpacket.uint16(firstp,tcphdr + 14)
							if tcpwinsize then
								ptcpwin = tonumber(tcpwinsize)
								if ptcpwin <= 65535 then
									--nw.logInfo("TCP WINDOW SIZE: " .. ptcpwin)
									nw.createMeta(self.keys["tcp.window_size"], ptcpwin)
									windowsize = ptcpwin
								end
							end
							
							-- TCP Options would start at the 20th byte offset from 0
							-- in the TCP header
							local tcpoptstart = tcphdr + 20
							local tcpoptstop = (tcpoptstart + headerlen - 8)	
							local payload = nwpacket.tostring(firstp,tcpoptstart, tcpoptstop)
							local stream = string.tohex(payload)
							if stream then
								
								tcpoptions = ({
								-- kind, length
									["00"] = 2, -- End of Option List (eol)
									["01"] = 2, -- No-Operation (nop)
									["02"] = 8, -- Maximum Segment Size (mss)
									["03"] = 6, -- Window Scale (ws)
									["04"] = 4, -- SACK Permitted (sok)
									["08"] = 20 -- Timestamps (ts)
								})
								
								tcpoptname = ({
								-- kind, length
									["00"] = "eol", -- End of Option List (eol)
									["01"] = "nop", -- No-Operation (nop)
									["02"] = "mss", -- Maximum Segment Size (mss)
									["03"] = "ws", -- Window Scale (ws)
									["04"] = "sok", -- SACK Permitted (sok)
									["08"] = "ts" -- Timestamps (ts)
								})

								tcpoptorder = {}

								current_position = 1
								len = string.len(stream)
								
								while current_position < len do
									opt = string.sub(stream, current_position, current_position +1)
									--nw.logInfo("OPT: " .. opt)
									if tcpoptions[opt] then  
										if tcpoptname[opt] then                                                                                                                                               
											j = tcpoptions[opt]  
											o = tcpoptname[opt]                                                                                                                                                     
											readin = string.sub(stream, current_position, current_position + j -1) 
											--nw.logInfo("READIN: " .. readin)
																				
											if opt == "02" then
												--nw.logInfo("02: " .. readin)
												mss = string.sub(readin, 5, -1)
												if mss then
													mssnum = tonumber(mss, 16)
													if mssnum then
														table.insert(tcpoptorder, o) 
														nw.createMeta(self.keys["max.segment_size"], mssnum)
													end
												end
											elseif opt == "03" then
												ws = string.sub(readin, 5,-1)
												if ws then
													wsnum = tonumber(ws, 16)
													if wsnum then
														table.insert(tcpoptorder, o) 
														nw.createMeta(self.keys["win.scale"], wsnum)
													end
												end
											
											else
												table.insert(tcpoptorder, o) 
											end
											                                                                                                  
										end
									end
									
									posf,posl = string.find(stream, readin, current_position)
									if posl then 
										current_position = posl +1
									else
										return
									end
								end

								ordlen = #tcpoptorder
								count = 0
								
								for i,j in ipairs(tcpoptorder) do 
									if j == "eol" then 
										count = count + 1
									end
								end								
								pad = count -1
								while pad > 0 do
									table.remove(tcpoptorder, ordlen)
									pad = pad -1
									ordlen = #tcpoptorder
								end
								if pad == 0 then
									tcpoptorder[ordlen] = ("eol+" .. count -1) 
								end
								
								local tcpeval = table.concat(tcpoptorder, ",")
								if tcpeval then
									local fingerprint = (ipversion .. ":" .. ttl .. ":" .. ipoptionslen .. ":" .. mssnum .. ":" .. ptcpwin .. "," .. wsnum .. ":" .. tcpeval .. ":" .. quirks .. ":0" )
									--nw.logInfo("FINGERPRINT: " .. fingerprint)
									nw.createMeta(self.keys["os.fingerprint"], fingerprint)
								end
								
							end
						end
					end
				end
			end
		end
	end
end	



passive_os_fingerprint:setCallbacks({
    [nwevents.OnSessionBegin] = passive_os_fingerprint.sessionBegin,
})
