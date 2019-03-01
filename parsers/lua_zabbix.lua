local lua_zabbix = nw.createParser("lua_zabbix", "Identify zabbix traffic")

--[[
    DESCRIPTION

        Identify zabbix network traffic and register into service.  
        

    VERSION
	
        2018-02-21 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
--]]




function lua_zabbix:sessionBegin()
	-- reset parser_state for the new session
	zabbixreq = nil
	zabbixresp = nil
	self.state = nil
end

function lua_zabbix:req(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 and dstport == 10050 or dstPort == 10051 then
		local requestStream = nwsession.getRequestStream()
		if requestStream then
			--nw.logInfo("*** ZABBIX REQUEST TOKEN MATCH: " .. token .. " ***")
			if zabbixresp == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notZABBIX) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(10051)
						--nw.logInfo("*** SERVICE 10051 ***")
						self.state.identified = true
					elseif service ~= 10051 then
						self.state.notZABBIX = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				zabbixreq = 1
			end
		end
	end				
end

function lua_zabbix:resp(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 and dstport == 10050 or dstPort == 10051 then
		local responseStream = nwsession.getResponseStream()
		if responseStream then
			--nw.logInfo("*** ZABBIX RESPONSE TOKEN MATCH: " .. token .. " ***")
			if zabbixreq == 1 then
				local status, error = pcall(function()
				self.state = self.state or {}
				if not (self.state.identified or self.state.notZABBIX) then
					local service = nw.getAppType()
					if not service or service == 0 then
						nw.setAppType(10051)
						--nw.logInfo("*** SERVICE 10051 ***")
						self.state.identified = true
					elseif service ~= 10051 then
						self.state.notZABBIX = true
					end
				end
				end)
				if not status and debugParser then
					nw.logFailure(error)
				end
			else
				zabbixresp = 1
			end
		end
	end				
end

function lua_zabbix:agent(token, first, last)
	local protocol, srcPort, dstPort  = nw.getTransport()
	if protocol == 6 and srcPort > 1024 and dstport == 10050 then
		local requestStream = nwsession.getRequestStream()
		if requestStream then			
			local status, error = pcall(function()
			self.state = self.state or {}
			if not (self.state.identified or self.state.notZABBIX) then
				local service = nw.getAppType()
				if not service or service == 0 then
					nw.setAppType(10051)
					--nw.logInfo("*** SERVICE 10051 ***")
					self.state.identified = true
				elseif service ~= 10051 then
					self.state.notZABBIX = true
				end
			end
			end)
			if not status and debugParser then
				nw.logFailure(error)
			end			
		end
	end				
end

lua_zabbix:setCallbacks({
	[nwevents.OnSessionBegin] = lua_zabbix.sessionBegin,
	["\90\66\88\68\01"] = lua_zabbix.req, -- 5a 42 58 44 01
	["\123\10\09\34\114\101\113\117\101\115\116\34\58"] = lua_zabbix.req, -- 7b 0a 09 22 72 65 71 75 65 73 74 22 3a
	["\34\114\101\113\117\101\115\116\34\58"] = lua_zabbix.req, -- "request":	
	["agent.hostname"] = lua_zabbix.agent,
	["agent\46ping"] = lua_zabbix.agent,
	["agent.version"] = lua_zabbix.agent,
	["kernel.maxfiles"] = lua_zabbix.agent,
	["kernel.maxproc"] = lua_zabbix.agent,
	["net.dns"] = lua_zabbix.agent,
	["net.if.collisions"] = lua_zabbix.agent,
	["net.if.discovery"] = lua_zabbix.agent,
	["net.if.in"] = lua_zabbix.agent,
	["net.if.out"] = lua_zabbix.agent,
	["net.if.total"] = lua_zabbix.agent,	
	["net.tcp.listen"] = lua_zabbix.agent,
	["net.tcp.port"] = lua_zabbix.agent,
	["net.tcp.service"] = lua_zabbix.agent,
	["net.udp.listen"] = lua_zabbix.agent,
	["net.udp.service"] = lua_zabbix.agent,	
	["proc.cpu.util"] = lua_zabbix.agent,	
	["proc.mem"] = lua_zabbix.agent,	
	["proc.num"] = lua_zabbix.agent,	
	["sensor"] = lua_zabbix.agent,
	["system.boottime"] = lua_zabbix.agent,		
	["system.cpu.discovery"] = lua_zabbix.agent,	
	["system.cpu.intr"] = lua_zabbix.agent,
	["system.cpu.load"] = lua_zabbix.agent,
	["system.cpu.num"] = lua_zabbix.agent,
	["system.cpu.switches"] = lua_zabbix.agent,
	["system.cpu.util"] = lua_zabbix.agent,
	["system.hostname"] = lua_zabbix.agent,
	["system.hw.chassis"] = lua_zabbix.agent,
	["system.hw.cpu"] = lua_zabbix.agent,
	["system.hw.devices"] = lua_zabbix.agent,
	["system.hw.macaddr"] = lua_zabbix.agent,
	["system.localtime"] = lua_zabbix.agent,
	["system.run"] = lua_zabbix.agent,
	["system.stat"] = lua_zabbix.agent,
	["system.sw.arch"] = lua_zabbix.agent,
	["system.sw.os"] = lua_zabbix.agent,
	["system.sw.packages"] = lua_zabbix.agent,
	["system.swap.in"] = lua_zabbix.agent,
	["system.swap.out"] = lua_zabbix.agent,
	["system.swap.size"] = lua_zabbix.agent,
	["system.uname"] = lua_zabbix.agent,
	["system.uptime"] = lua_zabbix.agent,
	["system.users.num"] = lua_zabbix.agent,
	["vfs.dev.read"] = lua_zabbix.agent,
	["vfs.dev.write"] = lua_zabbix.agent,
	["vfs.file.cksum"] = lua_zabbix.agent,
	["vfs.file.contents"] = lua_zabbix.agent,
	["vfs.file.exists"] = lua_zabbix.agent,
	["vfs.file.md5sum"] = lua_zabbix.agent,
	["vfs.file.regexp"] = lua_zabbix.agent,
	["vfs.file.regmatch"] = lua_zabbix.agent,
	["vfs.file.size"] = lua_zabbix.agent,
	["vfs.file.time"] = lua_zabbix.agent,
	["vfs.fs.discovery"] = lua_zabbix.agent,
	["vfs.fs.inode"] = lua_zabbix.agent,
	["vfs.fs.size"] = lua_zabbix.agent,
	["vm.memory.size"] = lua_zabbix.agent,
	["web.page.get"] = lua_zabbix.agent,
	["web.page.perf"] = lua_zabbix.agent,
	["web.page.regexp"] = lua_zabbix.agent,
	["\90\66\88\68\01"] = lua_zabbix.resp, -- 5a 42 58 44 01
	["\34\100\97\116\97\34\58\91\93"] = lua_zabbix.resp, -- "data":[]
})

