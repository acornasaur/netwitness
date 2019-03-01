local lua_teamviewer = nw.createParser("lua_teamviewer", "Teamviewer detection")

--[[
    DESCRIPTION

        Identify Teamviewer traffic.  
        

    VERSION
	
		2019-01-03 - Changed get payload line to get payload from request stream only    
        2018-08-13 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    NOTES
    
    	Big thank you goes to Awake Security and to David Pearson.
    	https://awakesecurity.com/analyzing-teamviewer/
    	
    	tv_commands table came from the Wireshark Teamviewer Parser created by David Pearson
    	https://dl.awakesecurity.com/defcon/nw_re_tools/resources.html
        
    	
        
--]]
-- declare the meta keys we'll be registering meta with
lua_teamviewer:setKeys({
	-- no keys other than service which is handled differently
})

tv_commands = {}
tv_commands[10] = "CMD_IDENTIFY"
tv_commands[11] = "CMD_REQUESTCONNECT"
tv_commands[13] = "CMD_DISCONNECT"
tv_commands[14] = "CMD_VNCDISCONNECT"
tv_commands[15] = "CMD_TVCONNECTIONFAILED"
tv_commands[16] = "CMD_PING"
tv_commands[17] = "CMD_PINGOK"
tv_commands[18] = "CMD_MASTERCOMMAND"
tv_commands[19] = "CMD_MASTERRESPONSE"
tv_commands[20] = "CMD_CHANGECONNECTION"
tv_commands[21] = "CMD_NOPARTNERCONNECT"
tv_commands[22] = "CMD_CONNECTTOWAITINGTHREAD"
tv_commands[23] = "CMD_SESSIONMODE"
tv_commands[24] = "CMD_REQUESTROUTINGSESSION"
tv_commands[25] = "CMD_TIMEOUT"
tv_commands[26] = "CMD_JAVACONNECT"
tv_commands[27] = "CMD_KEEPALIVEBEEP"
tv_commands[28] = "CMD_REQUESTKEEPALIVE"
tv_commands[29] = "CMD_MASTERCOMMAND_ENCRYPTED"
tv_commands[30] = "CMD_MASTERRESPONSE_ENCRYPTED"
tv_commands[31] = "CMD_REQUESTRECONNECT"
tv_commands[32] = "CMD_RECONNECTTOWAITINGTHREAD"
tv_commands[33] = "CMD_STARTLOGGING"
tv_commands[34] = "CMD_SERVERAVAILABLE"
tv_commands[35] = "CMD_KEEPALIVEREQUEST"
tv_commands[36] = "CMD_OK"
tv_commands[37] = "CMD_FAILED"
tv_commands[38] = "CMD_PING_PERFORMANCE"
tv_commands[39] = "CMD_PING_PERFORMANCE_RESPONSE"
tv_commands[40] = "CMD_REQUESTKEEPALIVE2"
tv_commands[41] = "CMD_DISCONNECT_SWITCHEDTOUDP"
tv_commands[42] = "CMD_SENDMODE_UDP"
tv_commands[43] = "CMD_KEEPALIVEREQUEST_ANSWER"
tv_commands[44] = "CMD_ROUTE_CMD_TO_CLIENT"
tv_commands[45] = "CMD_NEW_MASTERLOGIN"
tv_commands[46] = "CMD_BUDDY"
tv_commands[47] = "CMD_ACCEPTROUTINGSESSION"
tv_commands[48] = "CMD_NEW_MASTERLOGIN_ANSWER"
tv_commands[49] = "CMD_BUDDY_ENCRYPTED"
tv_commands[50] = "CMD_REQUEST_ROUTE_BUDDY"
tv_commands[51] = "CMD_CONTACT_OTHER_MASTER"
tv_commands[52] = "CMD_REQUEST_ROUTE_ENCRYPTED"
tv_commands[53] = "CMD_ENDSESSION"
tv_commands[54] = "CMD_SESSIONID"
tv_commands[55] = "CMD_RECONNECT_TO_SESSION"
tv_commands[56] = "CMD_RECONNECT_TO_SESSION_ANSWER"
tv_commands[57] = "CMD_MEETING_CONTROL"
tv_commands[58] = "CMD_CARRIER_SWITCH"
tv_commands[59] = "CMD_MEETING_AUTHENTICATION"
tv_commands[60] = "CMD_ROUTERCMD"
tv_commands[61] = "CMD_PARTNERRECONNECT"
tv_commands[62] = "CMD_CONGRESTION_CONTROL"
tv_commands[63] = "CMD_ACK"
tv_commands[70] = "CMD_UDPREQUESTCONNECT"
tv_commands[71] = "CMD_UDPPING"
tv_commands[72] = "CMD_UDPREQUESTCONNECT_VPN"
tv_commands[90] = "CMD_DATA"
tv_commands[91] = "CMD_DATA2"
tv_commands[92] = "CMD_DATA_ENCRYPTED"
tv_commands[93] = "CMD_REQUESTENCRYPTION"
tv_commands[94] = "CMD_CONFIRMENCRYPTION"
tv_commands[95] = "CMD_ENCRYPTIONREQUESTFAILED"
tv_commands[96] = "CMD_REQUESTNOENCRYPTION"
tv_commands[97] = "CMD_UDPFLOWCONTROL"
tv_commands[98] = "CMD_DATA3"
tv_commands[99] = "CMD_DATA3_ENCRYPTED"
tv_commands[100] = "CMD_DATA3_RESENDPACKETS"
tv_commands[101] = "CMD_DATA3_ACKPACKETS"
tv_commands[102] = "CMD_AUTH_CHALLENGE"
tv_commands[103] = "CMD_AUTH_RESPONSE"
tv_commands[104] = "CMD_AUTH_RESULT"
tv_commands[105] = "CMD_RIP_MESSAGES"
tv_commands[106] = "CMD_DATA4"
tv_commands[107] = "CMD_DATASTREAM"
tv_commands[108] = "CMD_UDPHEARTBEAT"
tv_commands[109] = "CMD_DATA_DIRECTED"
tv_commands[110] = "CMD_UDP_RESENDPACKETS"
tv_commands[111] = "CMD_UDP_ACKPACKETS"
tv_commands[112] = "CMD_UDP_PROTECTEDCOMMAND"
tv_commands[113] = "CMD_FLUSHSENDBUFFER"


function lua_teamviewer:sessionBegin()	

	self.state = nil
	--self.udpstate = nil
	
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 then
	-- Focusing on TCP request streams only
		local requestStream = nwsession.getRequestStream()	
		if requestStream then	
			-- request 8 bytes of payload
			local payload = nw.getPayload(requestStream,1,8) -- updated 2019-01-03 CWA 
			-- make sure we have 8 bytes of payload
			if payload and #payload == 8 then
				local magic = payload:uint16(1,2)
				-- check to make sure bytes 1 and 2 are 0x17 0x24 or 0x11 0x30.  
				if magic == 5924 then
					local command = payload:uint8(3)
					-- check to make sure byte 3 is a byte in our list
					local cmdcheck = tv_commands[command]
					if cmdcheck then 
						-- check to make sure bytes 4 and 5 (length) are greater than or equal to 1
						local tvlen = payload:uint16(4,5)
						if tvlen >= 1 then
							local status, error = pcall(function()
							self.state = self.state or {}
							if not (self.state.identified or self.state.nottv) then
								local service = nw.getAppType()
								if not service or service == 0 then
									nw.setAppType(5938)
									self.state.identified = true
								elseif service ~= 5938 then
									self.state.nottv = true
								end
							end
							end)
							if not status and debugParser then
								nw.logFailure(error)
							end		
						end
					end
				elseif magic == 4400 then
					local command = payload:uint8(3)
					-- check to make sure byte 3 is a byte in our list
					local cmdcheck = tv_commands[command]
					if cmdcheck then 
						-- check to see if byte 4 is actually 0x00
						local nullcheck = payload:uint8(4)
						if nullcheck == 0 then
							-- check to make sure bytes 5 - 8 (length) are greater than or equal to 1
							local tvlen = payload:uint32(5,8)
							if tvlen >= 1 then
								local status, error = pcall(function()
								self.state = self.state or {}
								if not (self.state.identified or self.state.nottv) then
									local service = nw.getAppType()
									if not service or service == 0 then
										nw.setAppType(5938)
										self.state.identified = true
									elseif service ~= 5938 then
										self.state.nottv = true
									end
								end
								end)
								if not status and debugParser then
									nw.logFailure(error)
								end		
							end
						end
					end

				end

			end
		end
	elseif protocol == 17 then
		-- request 64 bytes of payload
		local payload = nw.getPayload(1,64)
		-- make sure we have 64 bytes of payload
		if payload and #payload == 64 then
			local udptoken = payload:find("\0\0\0\0\0\0\0\0\0\0\3\23\36\71\80\0", 1, -1) -- 00 00 03 17 24 47 50 00
			if udptoken then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.nottv) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(5938)
						self.state.identified = true
					elseif service ~= 5938 then
						self.state.nottv = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end	
			end
		end	
	end		
end	



lua_teamviewer:setCallbacks({
	[nwevents.OnSessionBegin] = lua_teamviewer.sessionBegin,
})