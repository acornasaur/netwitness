local lua_interesting_commands = nw.createParser("lua_interesting_commands", "Creates meta if interesting string is seen")

-- Write meta into the following meta key(s)
lua_interesting_commands:setKeys({
	nwlanguagekey.create("ioc",nwtypes.Text),
	nwlanguagekey.create("analysis.session",nwtypes.Text),
	nwlanguagekey.create("analysis.service",nwtypes.Text),
})

function isBase64(s)
--return (s:len() >= 4) and (s:len() % 4 == 0) and not s:match('[^%a%d%+%/=]+')
return (s:len() >= 4) and not s:match('[^%a%d%+%/=]+')
end

function lua_interesting_commands:sessionBegin()
	-- reset parser_state for the new session
	self.parser_state = nil
	dcoutcount = {}
	qusercount = {}
	koadic = {}
end


function lua_interesting_commands:b64(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "base64-decode")		
end

function lua_interesting_commands:wscript(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "wscript-shell")		
end

function lua_interesting_commands:downloadString(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "downloadstring")		
end

function lua_interesting_commands:downloadFile(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "downloadFile")		
end

function lua_interesting_commands:WindowStyle(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "windowstyle")		
end

function lua_interesting_commands:BitsTransfer(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "bits-transfer")		
end

function lua_interesting_commands:pipedToSh(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "piped-to-sh")		
end

function lua_interesting_commands:curlSilentHTTP(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "silent-curl-http")		
end

function lua_interesting_commands:wgetSilentHTTP(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "silent-wget-http")		
end

function lua_interesting_commands:taskkillIM(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "taskkill-imagename")		
end

function lua_interesting_commands:ps1digit(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "pshell-one-digit-filename")		
end

function lua_interesting_commands:ps1char(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "pshell-one-char-filename")		
end

function lua_interesting_commands:comspec(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "comspec")		
end

function lua_interesting_commands:nopHidden(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "pshell-nop-hidden")		
end

function lua_interesting_commands:echoNetstat(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "echo-netstat")		
end

function lua_interesting_commands:echoHostname(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "echo-hostname")		
end

function lua_interesting_commands:echoOSQL(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "echo-osql")		
end

function lua_interesting_commands:echoSQLCMD(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "echo-sqlcmd")		
end

function lua_interesting_commands:echoStart(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "echo-start")		
end

function lua_interesting_commands:SEVENza(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "7za_command")		
end

function lua_interesting_commands:netstat(token, first, last)
	--if nw.isResponseStream() then
		-- register meta
		nw.createMeta(self.keys.ioc, "netstat_output")	
		--nw.logInfo("*** NETSTAT_OUTPUT ***")
	--end	
end

function lua_interesting_commands:loopback_admin(token, first, last)
	-- register meta
	nw.createMeta(self.keys.ioc, "loopback_admin_share")		
end

function lua_interesting_commands:powershellSeen(token, first, last)
	-- register meta
	nw.createMeta(self.keys["ioc"], "powershell")		
end

function lua_interesting_commands:xmrig(token, first, last)
	-- register meta
	nw.createMeta(self.keys["ioc"], "potential-xmrig-miner")		
end

function lua_interesting_commands:cmdFound(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "windows-command-line")		
end

function lua_interesting_commands:dosMode(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "dos-mode")		
end

function lua_interesting_commands:powershellNOP(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "powershell-nop")		
end

function lua_interesting_commands:powershellHidden(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "powershell-hidden")		
end

function lua_interesting_commands:curlSilent(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "curl-silent")		
end

function lua_interesting_commands:wgetSilent(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "wget-silent")		
end

function lua_interesting_commands:potentialTrickbot(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "potential-trickbot")		
end

function lua_interesting_commands:doubleBase64(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "double-b64")		
end

function lua_interesting_commands:powershellNonInteractive(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "powershell-non-interactive")		
end

function lua_interesting_commands:potentialMimikatz(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "potential-mimikatz")		
end

function lua_interesting_commands:potentialNetCat(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "potential-netcat")		
end

function lua_interesting_commands:pdfJar(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "pdf-jar")		
end

function lua_interesting_commands:exe1char(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "1char-exe")		
end

function lua_interesting_commands:schtasksObfusc(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "schtask-cmd-obfuscation")		
end

function lua_interesting_commands:cmdObfusc(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible-cmd-obfuscation")		
end

function lua_interesting_commands:squiblyDoo(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "potential-squiblydoo")		
end

function lua_interesting_commands:httpObfusc(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "http-obfuscation")		
end

function lua_interesting_commands:httpObfusc(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "pshell-obfuscation")		
end

function lua_interesting_commands:mshtaJavascript(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "mshta-javascript")		
end

function lua_interesting_commands:mshtaObfusc(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible-mshta-obfuscation")		
end

function lua_interesting_commands:msScriptXML(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "ms-script-xml")		
end

function lua_interesting_commands:possEmpire(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible-empire")		
end

function lua_interesting_commands:gzipB64(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible-gzip-b64")		
end

function lua_interesting_commands:powershellIOMemory(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "io-memorystream")		
end

function lua_interesting_commands:regRead(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "reg-read")		
end

function lua_interesting_commands:regWrite(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "reg-write")		
end

function lua_interesting_commands:file1char(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "one-char-file")		
end

function lua_interesting_commands:cdata(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "cdata")		
end

function lua_interesting_commands:taskScheduler(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "schtasks-create")		
end

function lua_interesting_commands:loopbackSMBAdmin(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "loopback-smb-admin")		
end

function lua_interesting_commands:possWmiExec(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible-wmiexec")		
end

function lua_interesting_commands:wmiWin32Process(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "wmi-win32process")		
end

function lua_interesting_commands:b64responsewrite(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "base64_responsewrite")		
end

function lua_interesting_commands:CreateObjectWscriptShell(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "hex_encoded_create_object_wscript_shell")		
end

function lua_interesting_commands:chinachopperpost(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_china_chopper")		
end

function lua_interesting_commands:DCOutput(token, first, last)
	if #dcoutcount <= 10 then
		table.insert(dcoutcount, token)
	end
	-- if we have at least 10 of our tokens in the table, then lets call it what it is
	if #dcoutcount == 10 then
		-- register meta 
		-- nw.logInfo("*** POSSIBLE_DOMAIN_CONTROLLER_OUTPUT ***")
		nw.createMeta(self.keys["ioc"], "possible_domain_controller_output")		
	end
end

function lua_interesting_commands:netuserOutput(token, first, last)
	current_position = last + 1
	local payload = nw.getPayload(current_position, current_position + 127)
	local dashdash = payload:find("-----------------------------------------", 1, -1)
		if dashdash then
		--register meta
		nw.createMeta(self.keys["ioc"], "possible_netuser_output")		
	end
end

function lua_interesting_commands:nltestOutput(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_nltest_output")		
end

function lua_interesting_commands:quserOutput(token, first, last)
	if #qusercount <= 6 then
		table.insert(qusercount, token)
	end
	-- if we have our tokens 6 in the table, then lets call it what it is
	if #qusercount == 6 then
		-- register meta 
		--nw.logInfo("*** POSSIBLE_QUSER_OUTPUT: " .. token .. " ***")
		nw.createMeta(self.keys["ioc"], "possible_quser_output")		
	end
end

function lua_interesting_commands:b64whois(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "base64_whois")		
end

function lua_interesting_commands:b64ipconfig(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "base64_ipconfig")		
end

function lua_interesting_commands:b64netusers(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "base64_net_users")		
end

function lua_interesting_commands:b64office(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "base64_office")		
end

function lua_interesting_commands:trickbot(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "trickbot")		
end

function lua_interesting_commands:hostLowerCase(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 then
		local requestStream = nwsession.getRequestStream()
		if requestStream then
			local service = nw.getAppType()
			if service == 80 then
				nw.createMeta(self.keys["ioc"], "http_lowercase_header")	
			end
		end
	end			
end

function lua_interesting_commands:CredDumper(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "cred_dumper_syntax")		
end

function lua_interesting_commands:tokenDECODE(token, first, last)
	current_position = first - 11                                                                                                                                                           
	local check = string.sub(stream, current_position, first + 1)  
	if check and check ~= nil then                                                                                                                               
		if string.lower(check) == "base64_decode" then                                                                                                                                          
			--register meta
			nw.createMeta(self.keys["ioc"], "suspicious_base64_decode")		                                                                                                                                                    
		end   
	end                                                                                                                                                                                  
end

function lua_interesting_commands:tokenCACTUS(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "cactustorch")		
end

function lua_interesting_commands:tokenB64ToStream(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "base64tostream")		
end

function lua_interesting_commands:tokenB64Transform(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "b64transform")		
end

function lua_interesting_commands:tokenASCIIEncoding(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "ascii_encoding")		
end

function lua_interesting_commands:tokenEntryClass(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "entry_class")		
end

function lua_interesting_commands:tokenScriptingFilesystemObject(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "scripting_filesystem_object")		
end

function lua_interesting_commands:tokenKoadic(token, first, last)
	if #koadic <= 5 then
		table.insert(koadic, token)
	end
	-- if we have our tokens 6 in the table, then lets call it what it is
	if #koadic == 5 then
		-- register meta 
		--nw.logInfo("*** POSSIBLE_QUSER_OUTPUT: " .. token .. " ***")
		nw.createMeta(self.keys["ioc"], "possible_koadic_output")		
	end
end

function lua_interesting_commands:tokenPEmpire(token, first, last)
	--nw.logInfo("*** COOKIE TOKEN MATCH ***")
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 then
		--nw.logInfo("COOKIE SERVICE MATCH")
		current_position = last + 1
		local payload = nw.getPayload(current_position, current_position + 63)
		local delim = payload:find("\13\10", 1, -1)
		if delim then
			--nw.logInfo("*** COOKIE FOUND DELIM ***")
			local session = payload:tostring(1, delim -1)
			local decode1 = nw.base64Decode(session)
			if decode1 then
				--nw.logInfo("META:  possible_powershell_empire_cookie")
				--register meta
				nw.createMeta(self.keys["ioc"], "suspicious_base64_cookie")	
			end
		end
	end			
end

-- This function, or some version of it, may wind up in HTTP_lua.
function lua_interesting_commands:metaCookie(index, meta)
	if #meta < 64 and not string.find(meta, "^.*;") then
		local val = string.match(meta, "^[^=]+=(.*)")
		if val then
			if isBase64(val) then
				nw.createMeta(self.keys["ioc"], "suspicious_base64_cookie")
			end
		end
	end
end

function lua_interesting_commands:tokenCobaltStrike(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "cobalt_strike_profile")		
end

function lua_interesting_commands:tokenBase64EXE(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "base64_exe")		
end

function lua_interesting_commands:tokenCreateObject(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "CreateObject")		
end

function lua_interesting_commands:tokenFSO(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "FileSystemObject")		
end

function lua_interesting_commands:tokenCreateMSXML(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "CreateMSXML")		
end

function lua_interesting_commands:tokenProcessorCount(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "ProcessorCount")		
end

function lua_interesting_commands:tokenSetStrictMode(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "StrictMode")		
end

function lua_interesting_commands:tokenOLEObject(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "ole_object")		
end

function lua_interesting_commands:tokenAccessVBOM(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "accessvbom")		
end

function lua_interesting_commands:tokenVBAProjectBin(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "vba_project_bin")		
end

function lua_interesting_commands:tokenVBAData(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "vba_data")		
end

function lua_interesting_commands:tokenDocProps(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "DocProps")		
end

function lua_interesting_commands:tokenB64cmdc(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "base64_cmd_c")		
end

function lua_interesting_commands:tokenVBAProjectCur(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "vba_project_cur")		
end

function lua_interesting_commands:tokenOLE10Native(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "ole10native")		
end

function lua_interesting_commands:tokenHEXEXE(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "hex_encoded_exe")		
end

function lua_interesting_commands:tokenVBAProject(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "vba_project")		
end

function lua_interesting_commands:tokenArchiveCreation(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "archive_file_creation")		
end

function lua_interesting_commands:tokenReverseHTTP(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "reverse_http_string")		
end

function lua_interesting_commands:tokenEmbeddedObject(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "embedded_object")		
end

function lua_interesting_commands:tokenFormsTextBox(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "forms_textbox")		
end

function lua_interesting_commands:tokenAttributeVBName(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "attribute_vbname")		
end

function lua_interesting_commands:tokenRARPassword(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_rar_password")		
end

function lua_interesting_commands:tokenARCHIVE(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_archive_creation")		
end

function lua_interesting_commands:tokenPDB(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "suspicious_pdb_string")		
end

function lua_interesting_commands:tokenREMCOM(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_remcom")		
end

function lua_interesting_commands:tokenSAMBA(token, first, last)
	--register meta
	nw.createMeta(self.keys["analysis.service"], "smb_samba")		
end

function lua_interesting_commands:tokenOPENVPN(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "openvpn_reference")		
end

function lua_interesting_commands:tokenBORLAND(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_borland_compiler")		
end

function lua_interesting_commands:tokenDELPHI(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_delphi_compiler")		
end

function lua_interesting_commands:tokenB64Invoke(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_b64_invoke")		
end

function lua_interesting_commands:tokenB64PasteBin(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_b64_pastebin")		
end

function lua_interesting_commands:tokenDRSUAPI(token, first, last)
	--register meta
	nw.createMeta(self.keys["analysis.service"], "drsuapi")		
end

function lua_interesting_commands:tokenDIRLIST(token, first, last)
	--register meta
	nw.createMeta(self.keys["analysis.service"], "directory_listing")		
end

function lua_interesting_commands:tokenExtraSpace(token, first, last)
	--register meta
	nw.createMeta(self.keys["analysis.service"], "http_extraneous_space_after_ok")		
end

function lua_interesting_commands:tokenREMCOS(token, first, last)
	--register meta
	nw.createMeta(self.keys["ioc"], "possible_remcos")		
end

function lua_interesting_commands:tokenAPOSTT(token, first, last)
	if first == 1 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			--register meta
			nw.createMeta(self.keys["ioc"], "possible_apost_t")		
		end
	end
end

function lua_interesting_commands:tokenLOKIBOT(token, first, last)
	if first <= 512 then
		local protocol, srcPort, dstPort  = nw.getTransport()
		if protocol == 6 and srcPort > 1024 then
			--register meta
			nw.createMeta(self.keys["ioc"], "possible_lokibot")		
		end
	end
end

function lua_interesting_commands:tokenPHP(token, first, last)
	--register meta
	nw.createMeta(self.keys["analysis.service"], "php")		
end

function lua_interesting_commands:tokenEVAL(token, first, last)
	--register meta
	nw.createMeta(self.keys["analysis.service"], "eval")		
end

function lua_interesting_commands:tokenB64DECODE(token, first, last)
	--register meta
	nw.createMeta(self.keys["analysis.service"], "base64_decode")		
end

lua_interesting_commands:setCallbacks({
	[nwevents.OnSessionBegin] = lua_interesting_commands.sessionBegin,
	["::FromBase64String"] = lua_interesting_commands.b64,
	["::fRoMbasE64STRIng"] = lua_interesting_commands.b64,
	["::FRoMbasE64STRIng"] = lua_interesting_commands.b64,
	["::FRoMbaSE64STRIng"] = lua_interesting_commands.b64,
	["FromBase64StrinG"] = lua_interesting_commands.b64,
	["WScript.shell"] = lua_interesting_commands.wscript,
	["WScript.Shell"] = lua_interesting_commands.wscript,
	["Wscript.Shell"] = lua_interesting_commands.wscript,
	["Wscript.shell"] = lua_interesting_commands.wscript,
	["wscript.shell"] = lua_interesting_commands.wscript,
	[".DownloadString("] = lua_interesting_commands.downloadString,
	[".downloadstring("] = lua_interesting_commands.downloadString,
	[".DownloadFile("] = lua_interesting_commands.downloadFile,
	["-WindowStyle Hidden"] = lua_interesting_commands.WindowStyle,
	["Start-BitsTransfer"] = lua_interesting_commands.BitsTransfer,
	["BITS administration utility."] = lua_interesting_commands.BitsTransfer,
	["BITSADMIN version "] = lua_interesting_commands.BitsTransfer,
	["bitsadmin "] = lua_interesting_commands.BitsTransfer,
	["bitsadmin /create"] = lua_interesting_commands.BitsTransfer,lua_newproxy_block,
	["curl -s http://"] = lua_interesting_commands.curlSilentHTTP,
	["curl -s"] = lua_interesting_commands.curlSilent,
	["wget -q http://"] = lua_interesting_commands.wgetSilentHTTP,
	["wget -q"] = lua_interesting_commands.wgetSilent,
	["taskkill /IM"] = lua_interesting_commands.taskkillIM,
	["taskkill /im"] = lua_interesting_commands.taskkillIM,
	["taskkill.exe /f /im "] = lua_interesting_commands.taskkillIM,
	["taskkill.exe /F /im "] = lua_interesting_commands.taskkillIM,
	["taskkill.exe /F /IM "] = lua_interesting_commands.taskkillIM,
	["/0.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/1.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/2.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/3.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/4.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/5.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/6.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/7.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/8.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/9.ps1 HTTP"] = lua_interesting_commands.ps1digit,
	["/a.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/b.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/c.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/d.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/e.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/f.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/g.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/h.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/i.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/j.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/k.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/l.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/m.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/n.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/o.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/p.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/q.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/r.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/s.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/t.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/u.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/v.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/w.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/x.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/y.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/z.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/A.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/B.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/C.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/D.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/E.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/F.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/G.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/H.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/I.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/J.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/K.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/L.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/M.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/N.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/O.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/P.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/Q.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/R.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/S.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/T.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/U.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/V.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/W.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/X.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/Y.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["/Z.ps1 HTTP"] = lua_interesting_commands.ps1char,
	["%COMSPEC%"] = lua_interesting_commands.comspec,
	["\37COMSPEC\037"] = lua_interesting_commands.comspec,
	["%COMSPEC:"] = lua_interesting_commands.comspec,
	["%.C.O.M.S"] = lua_interesting_commands.comspec,
	["%.c.o.m.s"] = lua_interesting_commands.comspec,
	["-nop -w hidden"] = lua_interesting_commands.nopHidden,
    ["echo netstat"] = lua_interesting_commands.echoNetstat,
    ["echo hostname"] = lua_interesting_commands.echoHostname,
    ["echo osql"] = lua_interesting_commands.echoOSQL,
    ["echo sqlcmd"] = lua_interesting_commands.echoSQLCMD,
    ["echo start "] = lua_interesting_commands.echoStart,
	["powershell "] = lua_interesting_commands.powershellSeen,
	["Powershell "] = lua_interesting_commands.powershellSeen,
	["powershell.exe"] = lua_interesting_commands.powershellSeen,
	["PowerShell "] = lua_interesting_commands.powershellSeen,
	["PowersHell "] = lua_interesting_commands.powershellSeen,
	["POwersHell "] = lua_interesting_commands.powershellSeen,
	["PowerSHell "] = lua_interesting_commands.powershellSeen,
	["PowersHelL "] = lua_interesting_commands.powershellSeen,
	["PoWersHell "] = lua_interesting_commands.powershellSeen,
	["PoWeRsHeLl "] = lua_interesting_commands.powershellSeen,
	["pOwErShElL "] = lua_interesting_commands.powershellSeen,
	["pOwERShElL "] = lua_interesting_commands.powershellSeen,
	["xmrig-xmr"] = lua_interesting_commands.xmrig,
	["Volume Serial Number is"] = lua_interesting_commands.cmdFound,
	["This program cannot be run in DOS mode"] = lua_interesting_commands.dosMode,
	[" -NoP"] = lua_interesting_commands.powershellNOP,
	[" -noP"] = lua_interesting_commands.powershellNOP,
	[" -W Hidden"] = lua_interesting_commands.powershellHidden,
	["digched"] = lua_interesting_commands.potentialTrickbot,
	["ADYANABTAHQAcgBpAG4AZ"] = lua_interesting_commands.doubleBase64,
	["ZQA2ADQAUwB0AHIAaQBuA"] = lua_interesting_commands.doubleBase64,
	["UANgA0AFMAdAByAGkAbgB"] = lua_interesting_commands.doubleBase64,
	["Invoke-Mimikatz"] = lua_interesting_commands.potentialMimikatz,
	["gentilkiwi"] = lua_interesting_commands.potentialMimikatz,
	["LSADUMP::"] = lua_interesting_commands.potentialMimikatz,
	["lsadump::"] = lua_interesting_commands.potentialMimikatz,
	["SEKURLSA::"] = lua_interesting_commands.potentialMimikatz,
	["sekurlsa::"] = lua_interesting_commands.potentialMimikatz,
	["privilege::debug"] = lua_interesting_commands.potentialMimikatz,
	["## / \ ##"] = lua_interesting_commands.potentialMimikatz,
	["Privilege '20' OK"] = lua_interesting_commands.potentialMimikatz,
	["mimikatz(commandline)"] = lua_interesting_commands.potentialMimikatz,
	["E.R.R.O.R. .k.u.l.l._.m._.a.s.n.1._.i.n.i.t"] = lua_interesting_commands.potentialMimikatz,
	["E.R.R.O.R. .k.u.l.l._.m._.b.u.s.y.l.i.g.h.t._.r.e.q.u.e.s.t._.c.r.e.a.t.e"] = lua_interesting_commands.potentialMimikatz,	
	["g.e.n.e.r.i.c._.c.e.r.t.i.f.i.c.a.t.e...d.o.m.a.i.n._.v.i.s.i.b.l.e._.p.a.s.s.w.o.r.d...d.o.m.a.i.n._.c.e.r.t.i.f.i.c.a.t.e"] = lua_interesting_commands.potentialMimikatz,	
	["E.R.R.O.R. .k.u.l.l._.m._.d.p.a.p.i._.u.n.p.r.o.t.e.c.t._.b.l.o.b"] = lua_interesting_commands.potentialMimikatz,	
	["E.R.R.O.R. .k.u.l.l._.m._.d.p.a.p.i._.u.n.p.r.o.t.e.c.t._.m.a.s.t.e.r.k.e.y._.w.i.t.h._.s.h.a.D.e.r.i.v.e.d.k.e.y"] = lua_interesting_commands.potentialMimikatz,	
	["E.R.R.O.R. .k.u.l.l._.m._.d.p.a.p.i._.u.n.p.r.o.t.e.c.t._.d.o.m.a.i.n.k.e.y._.w.i.t.h._.k.e.y"] = lua_interesting_commands.potentialMimikatz,
	["nc -l -p"] = lua_interesting_commands.potentialNetCat,
	["echo nc "] = lua_interesting_commands.potentialNetCat,
	["nc -v -n"] = lua_interesting_commands.potentialNetCat,
	["nc -w"] = lua_interesting_commands.potentialNetCat,
	["cmd /C"] = lua_interesting_commands.interestingCMD,
	["cmd.exe /C"] = lua_interesting_commands.interestingCMD,
	["cmd /Q"] = lua_interesting_commands.interestingCMD,
	["cmd.exe /Q"] = lua_interesting_commands.interestingCMD,
	["/a.exe HTTP"] = lua_interesting_commands.exe1char,
	["/b.exe HTTP"] = lua_interesting_commands.exe1char,
	["/c.exe HTTP"] = lua_interesting_commands.exe1char,
	["/d.exe HTTP"] = lua_interesting_commands.exe1char,
	["/e.exe HTTP"] = lua_interesting_commands.exe1char,
	["/f.exe HTTP"] = lua_interesting_commands.exe1char,
	["/g.exe HTTP"] = lua_interesting_commands.exe1char,
	["/h.exe HTTP"] = lua_interesting_commands.exe1char,
	["/i.exe HTTP"] = lua_interesting_commands.exe1char,
	["/j.exe HTTP"] = lua_interesting_commands.exe1char,
	["/k.exe HTTP"] = lua_interesting_commands.exe1char,
	["/l.exe HTTP"] = lua_interesting_commands.exe1char,
	["/m.exe HTTP"] = lua_interesting_commands.exe1char,
	["/n.exe HTTP"] = lua_interesting_commands.exe1char,
	["/o.exe HTTP"] = lua_interesting_commands.exe1char,
	["/p.exe HTTP"] = lua_interesting_commands.exe1char,
	["/q.exe HTTP"] = lua_interesting_commands.exe1char,
	["/r.exe HTTP"] = lua_interesting_commands.exe1char,
	["/s.exe HTTP"] = lua_interesting_commands.exe1char,
	["/t.exe HTTP"] = lua_interesting_commands.exe1char,
	["/u.exe HTTP"] = lua_interesting_commands.exe1char,
	["/v.exe HTTP"] = lua_interesting_commands.exe1char,
	["/w.exe HTTP"] = lua_interesting_commands.exe1char,
	["/x.exe HTTP"] = lua_interesting_commands.exe1char,
	["/y.exe HTTP"] = lua_interesting_commands.exe1char,
	["/z.exe HTTP"] = lua_interesting_commands.exe1char,
	["BaSE64_dEcOdE"] = lua_interesting_commands.b64,
	["sc^h^t^a^sk^s"] = lua_interesting_commands.schtasksObfusc,
	["s^c^h^t^a^sk^s"] = lua_interesting_commands.schtasksObfusc,
	["s^c^h^t^a^s^k^s"] = lua_interesting_commands.schtasksObfusc,
	["c^m^d "] = lua_interesting_commands.cmdObfusc, --can be noisy
	["cm^d "] = lua_interesting_commands.cmdObfusc, --can be noisy
	["C^m^D "] = lua_interesting_commands.cmdObfusc, --can be noisy
	["c^M^d "] = lua_interesting_commands.cmdObfusc, --can be noisy
	["Cm^d "] = lua_interesting_commands.cmdObfusc, --can be noisy
	["CM^d "] = lua_interesting_commands.cmdObfusc, --can be noisy
	["CM^D "] = lua_interesting_commands.cmdObfusc, --can be noisy
	["C^MD "] = lua_interesting_commands.cmdObfusc, --can be noisy
	["c^md "] = lua_interesting_commands.cmdObfusc, --can be noisy
	["/s /n /u /i:"] = lua_interesting_commands.squiblyDoo,
	["/i:http://"] = lua_interesting_commands.squiblyDoo,
	[" scrobj.dll"] = lua_interesting_commands.squiblyDoo,
	["ht'+'\"+\"tp://"] = lua_interesting_commands.httpObfusc,
	["p^o^w^"] = lua_interesting_commands.pshellObfusc,
	["P^o^w^"] = lua_interesting_commands.pshellObfusc,
	["p^o^W^"] = lua_interesting_commands.pshellObfusc,
	["p^O^w^"] = lua_interesting_commands.pshellObfusc,
	["P^o^W^"] = lua_interesting_commands.pshellObfusc,
	["p^o^we"] = lua_interesting_commands.pshellObfusc,
	["P^o^we"] = lua_interesting_commands.pshellObfusc,
	["p^o^We"] = lua_interesting_commands.pshellObfusc,
	["p^O^we"] = lua_interesting_commands.pshellObfusc,
	["P^o^We"] = lua_interesting_commands.pshellObfusc,
	["p^o^wE"] = lua_interesting_commands.pshellObfusc,
	["P^o^wE"] = lua_interesting_commands.pshellObfusc,
	["p^o^WE"] = lua_interesting_commands.pshellObfusc,
	["p^O^wE"] = lua_interesting_commands.pshellObfusc,
	["P^o^WE"] = lua_interesting_commands.pshellObfusc,
	["mshta.exe javascript"] = lua_interesting_commands.mshtaJavascript,
	["m^s^ht"] = lua_interesting_commands.mshtaObfusc,
	["ms^ht"] = lua_interesting_commands.mshtaObfusc,
	["m^sht"] = lua_interesting_commands.mshtaObfusc,
	["m^s^h^t"] = lua_interesting_commands.mshtaObfusc,
	["msh^t"] = lua_interesting_commands.mshtaObfusc,
	["<ms:script "] = lua_interesting_commands.msScriptXML,
--	["This is the default web page for this server"] = lua_interesting_commands.possEmpire,
	["IO.MemoryStream"] = lua_interesting_commands.powershellIOMemory,
	["IO.StreamReader"] = lua_interesting_commands.powershellIOMemory,
	[".RegRead"] = lua_interesting_commands.regRead,
	[".RegWrite"] = lua_interesting_commands.regWrite,
	["/a HTTP"] = lua_interesting_commands.file1char,
	["/b HTTP"] = lua_interesting_commands.file1char,
	["/c HTTP"] = lua_interesting_commands.file1char,
	["/d HTTP"] = lua_interesting_commands.file1char,
	["/e HTTP"] = lua_interesting_commands.file1char,
	["/f HTTP"] = lua_interesting_commands.file1char,
	["/g HTTP"] = lua_interesting_commands.file1char,
	["/h HTTP"] = lua_interesting_commands.file1char,
	["/i HTTP"] = lua_interesting_commands.file1char,
	["/j HTTP"] = lua_interesting_commands.file1char,
	["/k HTTP"] = lua_interesting_commands.file1char,
	["/l HTTP"] = lua_interesting_commands.file1char,
	["/m HTTP"] = lua_interesting_commands.file1char,
	["/n HTTP"] = lua_interesting_commands.file1char,
	["/o HTTP"] = lua_interesting_commands.file1char,
	["/p HTTP"] = lua_interesting_commands.file1char,
	["/q HTTP"] = lua_interesting_commands.file1char,
	["/r HTTP"] = lua_interesting_commands.file1char,
	["/s HTTP"] = lua_interesting_commands.file1char,
	["/t HTTP"] = lua_interesting_commands.file1char,
	["/u HTTP"] = lua_interesting_commands.file1char,
	["/v HTTP"] = lua_interesting_commands.file1char,
	["/w HTTP"] = lua_interesting_commands.file1char,
	["/x HTTP"] = lua_interesting_commands.file1char,
	["/y HTTP"] = lua_interesting_commands.file1char,
	["/z HTTP"] = lua_interesting_commands.file1char,
	["schtasks /create"] = lua_interesting_commands.taskScheduler,
	["/create /sc"] = lua_interesting_commands.taskScheduler,
	["\\\\127.0.0.1\\ADMIN"] = lua_interesting_commands.loopbackSMBAdmin,
	["PARAMETERS..cmd.exe /Q /c"] = lua_interesting_commands.possWmiExec,
	["Win32_ProcessStartup"] = lua_interesting_commands.wmiWin32Process,
	["%COMSPEC%"] = lua_interesting_commands.comspec,
	["-nop -w hidden"] = lua_interesting_commands.nopHidden,
    ["echo netstat"] = lua_interesting_commands.echoNetstat,
    ["echo hostname"] = lua_interesting_commands.echoHostname,
    ["echo osql"] = lua_interesting_commands.echoOSQL,
    ["echo sqlcmd"] = lua_interesting_commands.echoSQLCMD,
    ["echo start"] = lua_interesting_commands.echoStart,
    ["Usage: 7za <command>"] = lua_interesting_commands.SEVENza,
    ["0\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["0\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["0\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["1\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["2\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["3\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["4\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["5\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["6\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["7\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["8\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["9\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["0\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["0\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["0\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32\32\32\32\32ESTABLISHED"] = lua_interesting_commands.netstat,
    ["0\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["0\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["0\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["1\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["2\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["3\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["4\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["5\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["6\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["7\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["8\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["9\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["0\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["0\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["0\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["1\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["2\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["3\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["4\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["5\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["6\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["7\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["8\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["9\32\32\32\32\32\32\32\32LISTENING"] = lua_interesting_commands.netstat,
    ["\92\0\92\0\49\0\50\0\55\0\46\0\48\0\46\0\48\0\46\0\49\0\92\0\65\0\68\0\77\0\73\0\78\0\36\0"] = lua_interesting_commands.loopback_admin, --\\127.0.0.1\ADMIN$
    ["UmVzcG9uc2UuV3JpdGUo"] = lua_interesting_commands.b64responsewrite,
    ["526573706F6E73652E577269746528"] = lua_interesting_commands.b64responsewrite,
    ["3D4372656174654F626A6563742822777363726970742E7368656C6C22292E65786563"] = lua_interesting_commands.CreateObjectWscriptShell,
    ["3C3F70687020406576616C28245F504F53545B27636D64275D293B3F3E"] = lua_interesting_commands.chinachopperpost,
    [",OU=Domain Controllers,DC="] = lua_interesting_commands.DCOutput,
	[",OU=Workstations,OU="] = lua_interesting_commands.DCOutput,
	[",OU=Servers,OU="] = lua_interesting_commands.DCOutput,
	["User accounts for\32\92\92"] = lua_interesting_commands.netuserOutput,
	["List of domain trusts:\13\10\32\32\32\32"] = lua_interesting_commands.nltestOutput,
	["nltest /domain_trusts"] = lua_interesting_commands.nltestOutput,
	["Enumerating domain trusts"] = lua_interesting_commands.nltestOutput,
	["1717 0x6b5 RPC_S_UNKNOWN_IF"] = lua_interesting_commands.nltestOutput,	
	["USERNAME\32\32\32\32"] = lua_interesting_commands.quserOutput,
	["\32\32SESSIONNAME\32\32"] = lua_interesting_commands.quserOutput,
	["\32\32ID\32\32"] = lua_interesting_commands.quserOutput,
	["\32\32STATE\32\32"] = lua_interesting_commands.quserOutput,
	["\32\32IDLETIME\32\32"] = lua_interesting_commands.quserOutput,
	["\32\32LOGON TIME\13\10"] = lua_interesting_commands.quserOutput,
	["dwBoAG8AYQBtAGkA"] = lua_interesting_commands.b64whois,
	["aQBwAGMAbwBuAGYAaQBnAA"] = lua_interesting_commands.b64ipconfig,
	["bgBlAHQAIAB1AHMAZQByAHMA"] = lua_interesting_commands.b64netusers,
	["0M8R4KGxGuE"] = lua_interesting_commands.b64office,
	["\45\45\65\114\97\115\102\106\97\115\117\55\13\10\67\111\110\116\101\110\116\45\68\105\115\112\111\115\105\116\105\111\110\58\32"] = lua_interesting_commands.trickbot,
	["^host: "] = lua_interesting_commands.hostLowerCase,
	["^cookie: "] = lua_interesting_commands.hostLowerCase,
	["^connection: "] = lua_interesting_commands.hostLowerCase,	
	["'applocker.psd13'"] = lua_interesting_commands.CredDumper,	
	["Fail To Search LSASS Data"] = lua_interesting_commands.CredDumper,
	["DE&Z1="] = lua_interesting_commands.tokenDECODE,
	["DE&z1="] = lua_interesting_commands.tokenDECODE,
	["De&Z1="] = lua_interesting_commands.tokenDECODE,
	["De&z1="] = lua_interesting_commands.tokenDECODE,
	["dE&Z1="] = lua_interesting_commands.tokenDECODE,
	["dE&z1="] = lua_interesting_commands.tokenDECODE,
	["de&Z1="] = lua_interesting_commands.tokenDECODE,
	["de&z1="] = lua_interesting_commands.tokenDECODE,
--	["AAEAAAD/////AQAAAAAAAAA"] = lua_interesting_commands.tokenCACTUS,
	["base64ToStream"] = lua_interesting_commands.tokenB64ToStream,
	["System.Security.Cryptography.FromBase64Transform"] = lua_interesting_commands.tokenB64Transform,
	["System.Text.ASCIIEncoding"] = lua_interesting_commands.tokenASCIIEncoding,
	[" entry_class "] = lua_interesting_commands.tokenEntryClass,
	["Scripting.FileSystemObject"] = lua_interesting_commands.tokenScriptingFilesystemObject,
	["STAGER :"] = lua_interesting_commands.tokenKoadic,
	["SESSIONKEY :"] = lua_interesting_commands.tokenKoadic,
	["JOBKEY :"] = lua_interesting_commands.tokenKoadic,
	["JOBKEYPATH :"] = lua_interesting_commands.tokenKoadic,
	["EXPIRE :"] = lua_interesting_commands.tokenKoadic,
	["Cookie: session="] = lua_interesting_commands.tokenPEmpire,
	["Cookie: SESSIONID="] = lua_interesting_commands.tokenPEmpire,
	["Cookie: SESSION="] = lua_interesting_commands.tokenPEmpire,
	[nwlanguagekey.create("cookie", nwtypes.Text)] = lua_interesting_commands.metaCookie,
	["Sorry, no data corresponding your request."] = lua_interesting_commands.tokenCobaltStrike,
	["4C1158CCBAFC4896AD78ED0FF0F4A1B2"] = lua_interesting_commands.tokenCobaltStrike,
	["dbb8796a80d45e1f"] = lua_interesting_commands.tokenCobaltStrike,
	["^HTTP/1.1 200 OK "] = lua_interesting_commands.tokenExtraSpace,
    ["TVpaZgAASUkq"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqOAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVrvAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoJAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr5AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoGAAMAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr1AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoGAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoWAAMAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpFAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVptAQIAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoBAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpuAAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqOAAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVp3AAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpAAAEAAAAC"] = lua_interesting_commands.tokenBase64EXE,
    ["TVroAAAAAFtS"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoAAAEAAAAC"] = lua_interesting_commands.tokenBase64EXE,
    ["TVptAAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVrsAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoAAAAAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVrPAAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqFAA8AAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpF6D9PAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoAACIAAADA"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqkAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoAAAAAAAAA"] = lua_interesting_commands.tokenBase64EXE,
    ["TVryAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr4AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqLAAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoKAAIAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr0AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqEAAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVp4AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVp1AQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVo8AAEAAAAC"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqQAAMAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqAADMADgAI"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpSRf8lGgBA"] = lua_interesting_commands.tokenBase64EXE,
    ["TVp9AAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpQAAIAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpyAAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpLRVJORUwz"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpVAA0AAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoNAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr8AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoFAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVp1AAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoLAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoDAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr9AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoKAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVrxAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr/AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpZAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoEAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoHAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr3AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoCAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVq1AQcAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVrzAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqMAAIAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoMAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr7AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoAAgEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVr6AAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVp4AAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqAAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpgAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVruAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVp8AAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["TVpAAAEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVo5AQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVoQAQEAAAAE"] = lua_interesting_commands.tokenBase64EXE,
    ["TVqMAAMAAAAg"] = lua_interesting_commands.tokenBase64EXE,
    ["CreateObject("] = lua_interesting_commands.tokenCreateObject,
    ["CreateObject ("] = lua_interesting_commands.tokenCreateObject,
    ["Scripting.FileSystemObject"] = lua_interesting_commands.tokenFSO,
    ["CreateMSBuildXML"] = lua_interesting_commands.tokenCreateMSXML,
    ["objProcessorCount"] = lua_interesting_commands.tokenProcessorCount,
    ["U2V0LVN0cmljdE1vZGUgLVZlcnNpb24gMg"] = lua_interesting_commands.tokenSetStrictMode,
    ["oleObject1.bin"] = lua_interesting_commands.tokenOLEObject,
    ["Security\AccessVBOM"] = lua_interesting_commands.tokenAcessVBOM, 
    ["vbaProject.bin"] = lua_interesting_commands.tokenVBAProjectBin,
    ["vbaData.xml"] = lua_interesting_commands.tokenVBAData,
    ["docProps.core.xml"] = lua_interesting_commands.tokenDocProps,
    ["Y21kLmV4ZSAvYyA"] = lua_interesting_commands.tokenB64cmdc,
    ["Y21kIC9jIA"] = lua_interesting_commands.tokenB64cmdc,   
    ["WTIxa0xtVjRaU0F2WXlB"] = lua_interesting_commands.tokenB64cmdc,
    ["V\00B\00A\00_\00P\00R\00O\00J\00E\00C\00T\00_\00C\00U\00R"] = lua_interesting_commands.tokenVBAProjectCur,
    ["Ole10Native"] = lua_interesting_commands.tokenOLE10Native,
    ["\79\0\108\0\101\0\49\0\48\0\78\0\97\0\116\0\105\0\118\0\101"] = lua_interesting_commands.tokenOLE10Native,
    ["4D5A900003000000040000"] = lua_interesting_commands.tokenHEXEXE,
    ["\86\46\66\46\65\46\95\46\80\46\82\46\79\46\74\46\69\46\67\46\84\00"] = lua_interesting_commands.tokenVBAProject,
    ["\95\0\86\0\66\0\65\0\95\0\80\0\82\0\79\0\74\0\69\0\67\0\84\0"] = lua_interesting_commands.tokenVBAProject,
    ["Creating archive "] = lua_interesting_commands.tokenArchiveCreation,
    ["//:ptth"] = lua_interesting_commands.tokenReverseHTTP,
    ["Embedded Object"] = lua_interesting_commands.tokenEmbeddedObject,
    ["Forms.TextBox.1"] = lua_interesting_commands.tokenFormsTextBox,
    ["\65\116\116\114\105\98\117\116\0\101\32\86\66\95\78\97\109\0\101\32\61"] = lua_interesting_commands.tokenAttributeVBName,
    [" -hp"] = lua_interesting_commands.tokenRARpassword,
    ["Q3JlYXRpbmcgYXJjaGl2ZSB"] = lua_interesting_commands.tokenARCHIVE, 
    ["C:\92local0\92asf\92release\92build-2.2.14\92support\92Release\92ab.pdb"] = lua_interesting_commands.tokenPDB, 
    ["R.e.m.C.o.m._.c.o.m.m.u.n.i.c.a.t.o.n"] = lua_interesting_commands.tokenREMCOM, 
   	["\82\0\101\0\109\0\67\0\111\0\109\0\95\0\99\0\111\0\109\0\109\0\117\0\110\0\105\0\99\0\97\0\116\0\111\0\110"] = lua_interesting_commands.tokenREMCOM, 
   	["\0\2\83\97\109\98\97\0\2\78\84\32\76\65\78\77\65\78\32"] = lua_interesting_commands.tokenSAMBA,
   	["OpenVPN Server"] = lua_interesting_commands.tokenOPENVPN,
   	["Pierre le Riche / Professional Software"] = lua_interesting_commands.tokenBORLAND,
   	["Software\92Borland\92Delphi"] = lua_interesting_commands.tokenDELPHI,
   	["BJAG4AdgBvAGsAZQAt"] = lua_interesting_commands.tokenB64Invoke,
    ["HAAYQBzAHQAZQBiAGkAbgAuAGMAbwBt"] = lua_interesting_commands.tokenB64PasteBin,  	
    ["\53\66\81\227\6\75\209\17\171\4\0\192\79\194\220\210"] = lua_interesting_commands.tokenDRSUAPI, -- 35 42 51 e3 06 4b d1 11 ab 04 00 c0 4f c2 dc d2   
    ["<title>Directory listing for "] = lua_interesting_commands.tokenDIRLIST,
    ["\27\132\213\176\93\244\196\147\197\48\194"] = lua_interesting_commands.tokenREMCOS, -- 1b 84 d5 b0 5d f4 c4 93 c5 30 c2
    ["\53\0\0\0"] = lua_interesting_commands.tokenAPOSTT, -- 35 00 00 00 
    ["\18\0\39\0\0\0\7\0\0\0"] = lua_interesting_commands.tokenLOKIBOT, -- 12 00 27 00 00 00 07 00 00 00
    ["\18\0\40\0\0\0\7\0\0\0"] = lua_interesting_commands.tokenLOKIBOT, -- 12 00 28 00 00 00 07 00 00 00
    ["^<?php"] = lua_interesting_commands.tokenPHP,
    ["eval("] = lua_interesting_commands.tokenEVAL,
    ["eval ("] = lua_interesting_commands.tokenEVAL,
    ["base64_decode("] = lua_interesting_commands.tokenB64DECODE,
})
