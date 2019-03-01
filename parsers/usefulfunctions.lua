local string = require('string')
local bit = require('bit')
local table = require('table')
local tonumber = tonumber
local type = type
local ipairs = ipairs
local pairs = pairs
local math = require('math')
local pcall = pcall
--local debugParser = require('debugParser')
--local logInfo = nw.logInfo
--local print = print

module("findvalue")

--[[ 
	-----------
	 FIND LAST
	-----------

Find the last occurrence of a character in a string.  Useful for finding the last dot position.
--]]

function findLast(haystack, needle)
	local i = haystack:match(“.*”..needle..”()”)
	if i == nil then return nil else return i-1 end
end

--[[ 
	------------
	 FIND FIRST
	------------

Find the First occurrence of a character in a string.  Useful for finding the first dot position.
--]]


function findFirst(haystack, needle)
	local i = haystack:match(“()”..needle..”.*”)
	if i == nil then return nil else return i end
end


--[[ 
	------------
	 PRINT HEX
	------------

Print HEX output.  Useful for troubleshooting.
--]]

function toHexString(myPayload)
	local hexout = ''
	--nw.logInfo("ECCPayload:len() " .. ECCPayload:len()) 
	for i=1, myPayload:len() do
		hexout = hexout .. bit.tohex(myPayload:uint8(i),2) .. ' '
	end
	return hexout
end


--[[ 
	---------------
	 STRING TO HEX
	---------------

String TO HEX function.  Useful for troubleshooting.
--]]


function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end


--[[ 
	-----------------
	 STRING FROM HEX
	-----------------

String FROM HEX function.  Useful for troubleshooting.
--]]


function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end





