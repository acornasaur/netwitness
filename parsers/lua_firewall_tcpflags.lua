local lua_firewall_tcpflags = nw.createParser("lua_firewall_tcpflags", "Extract and normalize TCP flags from Firewall logs")

--[[
    DESCRIPTION

        Extract and normalize TCP flags from Firewall logs.  Started working with pfSense firewall logs and configured the log parser to extract the tcp flags as transient.
        Then, come in with lua parser to break out into individual flags (tcpflags) and all tcp flags seen in the session (tcp.flags.seen).
        
        This started with pfSense, but if the data is in other firewall logs, it should be possible to include additional sources.
        

    VERSION
	
        2019-07-05 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        None
        
    
    NOTES       
    	
    	https://docs.netgate.com/pfsense/en/latest/monitoring/filter-log-format-for-pfsense-2-2.html
    	
    
    EXAMPLE LOG
    
    	Jul 5 17:08:05 filterlog: 33,,,1000004861,igb0,match,pass,out,4,0x0,,127,630,0,DF,6,tcp,52,67.244.122.202,54.80.9.251,33537,443,0,S,2184416923,,64240,,mss;nop;wscale;nop;nop;sackOK

    	
--]]


-- declare the meta keys we'll be registering meta with
lua_firewall_tcpflags:setKeys({
	nwlanguagekey.create("tcpflags"), -- Register individual tcp flags just how it's used in packets.
	nwlanguagekey.create("tcp.flags.seen",nwtypes.Text), -- Register all tcp flags seen in the session just how it's used in packets.
})

-- This table maps the field value to the appropriately named tcp flag
local findflags = ({
	["S"] = "syn", 
	["A"] = "ack", 
	["P"] = "psh", 
	["R"] = "rst", 
	["F"] = "fin", 
	["U"] = "urg", 
	["E"] = "ece", 
	["W"] = "cwr", 
})

-- This table maps the appropriately named tcp flag to an integer value which will be counted up later (tcp.flags in packets)
local flags = ({       
	["fin"] = 1,
	["syn"] = 2,     
	["rst"] = 4,
	["psh"] = 8, 
	["ack"] = 16,
	["urg"] = 32,
	["ece"] = 64,
	["cwr"] = 128
})

-- This table maps the counted up summary of all the flags in the session and then displays them.
local flagsseen = ({
	[1] = "fin",
	[2] = "syn",
	[3] = "fin syn",
	[4] = "rst",
	[5] = "fin rst",
	[6] = "syn rst",
	[7] = "fin syn rst",
	[8] = "psh",
	[9] = "fin psh",
	[10] = "syn psh",
	[11] = "fin syn psh",
	[12] = "rst psh",
	[13] = "fin rst psh",
	[14] = "syn rst psh",
	[15] = "fin syn rst psh",
	[16] = "ack",
	[17] = "fin ack",
	[18] = "syn ack",
	[19] = "fin syn ack",
	[20] = "rst ack",
	[21] = "fin rst ack",
	[22] = "syn rst ack",
	[23] = "fin syn rst ack",
	[24] = "psh ack",
	[25] = "fin psh ack",
	[26] = "syn psh ack",
	[27] = "fin syn psh ack",
	[28] = "rst psh ack",
	[29] = "fin rst psh ack",
	[30] = "syn rst psh ack",
	[31] = "fin syn rst psh ack",
	[32] = "urg",
	[33] = "fin urg",
	[34] = "syn urg",
	[35] = "fin syn urg",
	[36] = "rst urg",
	[37] = "fin rst urg",
	[38] = "syn rst urg",
	[39] = "fin syn rst urg",
	[40] = "psh urg",
	[41] = "fin psh urg",
	[42] = "syn psh urg",
	[43] = "fin syn psh urg",
	[44] = "rst psh urg",
	[45] = "fin rst psh urg",
	[46] = "syn rst psh urg",
	[47] = "fin syn rst psh urg",
	[48] = "ack urg",
	[49] = "fin ack urg",
	[50] = "syn ack urg",
	[51] = "fin syn ack urg",
	[52] = "rst ack urg",
	[53] = "fin rst ack urg",
	[54] = "syn rst ack urg",
	[55] = "fin syn rst ack urg",
	[56] = "psh ack urg",
	[57] = "fin psh ack urg",
	[58] = "syn psh ack urg",
	[59] = "fin syn psh ack urg",
	[60] = "rst psh ack urg",
	[61] = "fin rst psh ack urg",
	[62] = "syn rst psh ack urg",
	[63] = "fin syn rst psh ack urg",
	[64] = "ece",
	[65] = "fin ece",
	[66] = "syn ece",
	[67] = "fin syn ece",
	[68] = "rst ece",
	[69] = "fin rst ece",
	[70] = "syn rst ece",
	[71] = "fin syn rst ece",
	[72] = "psh ece",
	[73] = "fin psh ece",
	[74] = "syn psh ece",
	[75] = "fin syn psh ece",
	[76] = "rst psh ece",
	[77] = "fin rst psh ece",
	[78] = "syn rst psh ece",
	[79] = "fin syn rst psh ece",
	[80] = "ack ece",
	[81] = "fin ack ece",
	[82] = "syn ack ece",
	[83] = "fin syn ack ece",
	[84] = "rst ack ece",
	[85] = "fin rst ack ece",
	[86] = "syn rst ack ece",
	[87] = "fin syn rst ack ece",
	[88] = "psh ack ece",
	[89] = "fin psh ack ece",
	[90] = "syn psh ack ece",
	[91] = "fin syn psh ack ece",
	[92] = "rst psh ack ece",
	[93] = "fin rst psh ack ece",
	[94] = "syn rst psh ack ece",
	[95] = "fin syn rst psh ack ece",
	[96] = "urg ece",
	[97] = "fin urg ece",
	[98] = "syn urg ece",
	[99] = "fin syn urg ece",
	[100] = "rst urg ece",
	[101] = "fin rst urg ece",
	[102] = "syn rst urg ece",
	[103] = "fin syn rst urg ece",
	[104] = "psh urg ece",
	[105] = "fin psh urg ece",
	[106] = "syn psh urg ece",
	[107] = "fin syn psh urg ece",
	[108] = "rst psh urg ece",
	[109] = "fin rst psh urg ece",
	[110] = "syn rst psh urg ece",
	[111] = "fin syn rst psh urg ece",
	[112] = "ack urg ece",
	[113] = "fin ack urg ece",
	[114] = "syn ack urg ece",
	[115] = "fin syn ack urg ece",
	[116] = "rst ack urg ece",
	[117] = "fin rst ack urg ece",
	[118] = "syn rst ack urg ece",
	[119] = "fin syn rst ack urg ece",
	[120] = "psh ack urg ece",
	[121] = "fin psh ack urg ece",
	[122] = "syn psh ack urg ece",
	[123] = "fin syn psh ack urg ece",
	[124] = "rst psh ack urg ece",
	[125] = "fin rst psh ack urg ece",
	[126] = "syn rst psh ack urg ece",
	[127] = "fin syn rst psh ack urg ece",
	[128] = "cwr",
	[129] = "fin cwr",
	[130] = "syn cwr",
	[131] = "fin syn cwr",
	[132] = "rst cwr",
	[133] = "fin rst cwr",
	[134] = "syn rst cwr",
	[135] = "fin syn rst cwr",
	[136] = "psh cwr",
	[137] = "fin psh cwr",
	[138] = "syn psh cwr",
	[139] = "fin syn psh cwr",
	[140] = "rst psh cwr",
	[141] = "fin rst psh cwr",
	[142] = "syn rst psh cwr",
	[143] = "fin syn rst psh cwr",
	[144] = "ack cwr",
	[145] = "fin ack cwr",
	[146] = "syn ack cwr",
	[147] = "fin syn ack cwr",
	[148] = "rst ack cwr",
	[149] = "fin rst ack cwr",
	[150] = "syn rst ack cwr",
	[151] = "fin syn rst ack cwr",
	[152] = "psh ack cwr",
	[153] = "fin psh ack cwr",
	[154] = "syn psh ack cwr",
	[155] = "fin syn psh ack cwr",
	[156] = "rst psh ack cwr",
	[157] = "fin rst psh ack cwr",
	[158] = "syn rst psh ack cwr",
	[159] = "fin syn rst psh ack cwr",
	[160] = "urg cwr",
	[161] = "fin urg cwr",
	[162] = "syn urg cwr",
	[163] = "fin syn urg cwr",
	[164] = "rst urg cwr",
	[165] = "fin rst urg cwr",
	[166] = "syn rst urg cwr",
	[167] = "fin syn rst urg cwr",
	[168] = "psh urg cwr",
	[169] = "fin psh urg cwr",
	[170] = "syn psh urg cwr",
	[171] = "fin syn psh urg cwr",
	[172] = "rst psh urg cwr",
	[173] = "fin rst psh urg cwr",
	[174] = "syn rst psh urg cwr",
	[175] = "fin syn rst psh urg cwr",
	[176] = "ack urg cwr",
	[177] = "fin ack urg cwr",
	[178] = "syn ack urg cwr",
	[179] = "fin syn ack urg cwr",
	[180] = "rst ack urg cwr",
	[181] = "fin rst ack urg cwr",
	[182] = "syn rst ack urg cwr",
	[183] = "fin syn rst ack urg cwr",
	[184] = "psh ack urg cwr",
	[185] = "fin psh ack urg cwr",
	[186] = "syn psh ack urg cwr",
	[187] = "fin syn psh ack urg cwr",
	[188] = "rst psh ack urg cwr",
	[189] = "fin rst psh ack urg cwr",
	[190] = "syn rst psh ack urg cwr",
	[191] = "fin syn rst psh ack urg cwr",
	[192] = "ece cwr",
	[193] = "fin ece cwr",
	[194] = "syn ece cwr",
	[195] = "fin syn ece cwr",
	[196] = "rst ece cwr",
	[197] = "fin rst ece cwr",
	[198] = "syn rst ece cwr",
	[199] = "fin syn rst ece cwr",
	[200] = "psh ece cwr",
	[201] = "fin psh ece cwr",
	[202] = "syn psh ece cwr",
	[203] = "fin syn psh ece cwr",
	[204] = "rst psh ece cwr",
	[205] = "fin rst psh ece cwr",
	[206] = "syn rst psh ece cwr",
	[207] = "fin syn rst psh ece cwr",
	[208] = "ack ece cwr",
	[209] = "fin ack ece cwr",
	[210] = "syn ack ece cwr",
	[211] = "fin syn ack ece cwr",
	[212] = "rst ack ece cwr",
	[213] = "fin rst ack ece cwr",
	[214] = "syn rst ack ece cwr",
	[215] = "fin syn rst ack ece cwr",
	[216] = "psh ack ece cwr",
	[217] = "fin psh ack ece cwr",
	[218] = "syn psh ack ece cwr",
	[219] = "fin syn psh ack ece cwr",
	[220] = "rst psh ack ece cwr",
	[221] = "fin rst psh ack ece cwr",
	[222] = "syn rst psh ack ece cwr",
	[223] = "fin syn rst psh ack ece cwr",
	[224] = "urg ece cwr",
	[225] = "fin urg ece cwr",
	[226] = "syn urg ece cwr",
	[227] = "fin syn urg ece cwr",
	[228] = "rst urg ece cwr",
	[229] = "fin rst urg ece cwr",
	[230] = "syn rst urg ece cwr",
	[231] = "fin syn rst urg ece cwr",
	[232] = "psh urg ece cwr",
	[233] = "fin psh urg ece cwr",
	[234] = "syn psh urg ece cwr",
	[235] = "fin syn psh urg ece cwr",
	[236] = "rst psh urg ece cwr",
	[237] = "fin rst psh urg ece cwr",
	[238] = "syn rst psh urg ece cwr",
	[239] = "fin syn rst psh urg ece cwr",
	[240] = "ack urg ece cwr",
	[241] = "fin ack urg ece cwr",
	[242] = "syn ack urg ece cwr",
	[243] = "fin syn ack urg ece cwr",
	[244] = "rst ack urg ece cwr",
	[245] = "fin rst ack urg ece cwr",
	[246] = "syn rst ack urg ece cwr",
	[247] = "fin syn rst ack urg ece cwr",
	[248] = "psh ack urg ece cwr",
	[249] = "fin psh ack urg ece cwr",
	[250] = "syn psh ack urg ece cwr",
	[251] = "fin syn psh ack urg ece cwr",
	[252] = "rst psh ack urg ece cwr",
	[253] = "fin rst psh ack urg ece cwr",
	[254] = "syn rst psh ack urg ece cwr",
	[255] = "fin syn rst psh ack urg ece cwr",
})

function lua_firewall_tcpflags:sessionBegin()
	-- reset variables for the new session
	flagsum = 0
end

function lua_firewall_tcpflags:flagsMeta(index, meta)
    for i,j in pairs(findflags) do
   		local match = i
   		local flag = j
   		if string.find(meta, match) then
			nw.createMeta(self.keys["tcpflags"], flag)
			if flags[flag] then
				flagsum = flagsum + flags[flag]
			end
		end
	end
	if flagsum > 0 then
		local flagsummary = flagsseen[flagsum]
		if flagsummary then
			nw.createMeta(self.keys["tcp.flags.seen"], flagsummary)
		end
	end
end


-- declare what tokens and events we want to match
lua_firewall_tcpflags:setCallbacks({
	[nwevents.OnSessionBegin] = lua_firewall_tcpflags.sessionBegin,
	[nwlanguagekey.create("tcpflags.trans")] = lua_firewall_tcpflags.flagsMeta, -- The meta callback key which is set to transient in our log parser.
})

