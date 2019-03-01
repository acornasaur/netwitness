local refererpath = nw.createParser("Referer_PATH", "Extract hostname, directory, filename, extension and querystring from referer.")

--[[
    DESCRIPTION

        Extract path data from referer


    VERSION
		
        2015-10-13 - Initial development
        
       
    AUTHOR
    
    	christopher.ahearn@rsa.com   
    
    
    DEPENDENCIES

        This parser requires 'nwll'.  
        
        You can download from Live (Search, Lua Parsers).  Extract the contents of the 
        nwll.zip file and upload via Administration/Log Decoder, Config, Parsers or place 
        in /etc/netwitness/ng/parsers directory on the Log Decoder.  It should already be
        there for packet decoders.
        
    META KEYS
    
    	<key description="Referer Host" level="IndexValues" name="referer.host" valueMax="1000000" format="Text"/>
    	<key description="Referer Directory" level="IndexValues" name="referer.dir" valueMax="1000000" format="Text"/>
    	<key description="Referer Filename" level="IndexValues" name="referer.file" valueMax="1000000" format="Text"/>
    	<key description="Referer Extension" level="IndexValues" name="referer.ext" valueMax="1000000" format="Text"/>    	    	
    	<key description="Referer Query" level="IndexValues" name="referer.query" valueMax="1000000" format="Text"/>
    	
   
    NOTES
    
		None
		
	
        
--]]

-- Since we are using an external module, we declare it here.  
-- This must be in the parsers directory
local nwll = require('nwll')

-- These are the meta keys that we will write meta into
refererpath:setKeys({
    nwlanguagekey.create("referer.host"),
    
    --[[
    nwlanguagekey.create("referer.dir"),
    nwlanguagekey.create("referer.file"),
    nwlanguagekey.create("referer.ext"),
    nwlanguagekey.create("referer.query"),
    --]]
})

-- This is our function.  What we want to do when we match a token...or in this case, the 
-- referer meta callback.

--[[               --------------------
                   EXTRACT URL ELEMENTS
                   --------------------

2013.06.14.1  william.motley@rsa.com  Initial development

Breaks out a url into host, directory, filename, extension, and querystring.

Expects a lua string, NOT payload!  (todo?)

Returns values similarly to extractPathElements().

IMPORTANT:  the "host" value returned must still be sent through determineHostType()

Example:

    local someURL = payload:tostring(x, y)
    local host, directory, filename, extension, querystring = nwll.extractUrlElements(someURL)
    if host then
        local key
        host, key = nwll.determineHostType(host)
        if host and key then
            nw.createMeta(self.keys[key], host)
        end
    end
    if directory then
        nw.createMeta(self.keys.directory, directory)
    end
    if filename then
        nw.createMeta(self.keys.filename, filename)
    end
    if extension then
        nw.createMeta(self.keys.extension, extension)
    end
    if querystring then
        nw.createMeta(self.keys.querystring, querystring)
    end

--]]

--[[
function extractUrlElements(path)
    -- Look for a "://" within the first few bytes.
    local stringFind, stringSub = string.find, string.sub
    local urlHost, urlDirectory, urlFilename, urlExtension, urlQuerystring
    local found = stringFind(path, "://")
    if found and found < 10 then
        -- yep, so separate host from path
        path = stringSub(path, found + 3, -1)
        found = stringFind(path, "/")
        if not found then
            -- no "/", maybe there is a "?"
            found = stringFind(path, "?")
        end
        if found then
            urlHost = stringSub(path, 1, found - 1)
            path = stringSub(path, found, -1)
        else
            -- if we didn't find a "/" or "?" then the entire thing is a host
            urlHost = path
            path = nil
        end
    else
        -- It could still be a host.  The only way to know for sure is if there is a port
        -- specified (e.g., CONNECT www.example.com:80 HTTP/1.1).  If there really isn't
        -- a port then there's nothing else we can do (it will be registered as a filename).
        found = stringFind(path, ":")
        if found then
            -- Make sure there isn't any path-type characters in front of it
            local char = stringFind(path, "[/\?\=\&]")
            if not char or char > found then
                -- In this case, the entire thing must be a host
                urlHost = path
                path = nil
            end
        end
    end
    if path then
        local directory, filename, extension, query
        -- Is there a querystring?  Look for the "?" indicator
        query = stringFind(path, "?")
        if query then
            urlDirectory, urlFilename, urlExtension = extractPathElements(stringSub(path, 1, query - 1))
            urlQuery = stringSub(path, query + 1, -1)
        else
            -- Didn't find a "?", but there may not be one if there is no filename.  Look for a "=".
            query = stringFind(path, "=")
            if query then
                -- There is a querystring, so there must not be a filename.  Look for the last directory marker ("/").
                query = 1
                repeat
                    local loopControl = 0
                    local foundDir = stringFind(path, "/", query)
                    if foundDir then
                        query = foundDir + 1
                        loopControl = 1
                    end
                until loopControl == 0
                urlDirectory, urlFilename, urlExtension = extractPathElements(stringSub(path, 1, query - 1))
                urlQuery = stringSub(path, query, -1)
            else
                -- There is no querystring
                urlDirectory, urlFilename, urlExtension = extractPathElements(path)
            end
        end
    end
    return urlHost, urlDirectory, urlFilename, urlExtension, urlQuery
end

--]]


function refererpath:refererMeta(index, meta)
    local somemeta = meta
    
    -- check if the referer contains the method (http:// or https:// typically) in first 
    -- few bytes
--	local first,last = string.find(meta, "://", 1,10)
--    if last then
--    	somemeta = string.sub(somemeta, last + 1, -1)
--    end	
    
    -- apply the nwll.extractUrlElements function from the nwll module		
    --local host, directory, filename, extension, querystring = nwll.extractUrlElements(somemeta)
    local host, directory, filename, extension, querystring = nwll.extractUrlElements(somemeta)
    if host then
       -- local key
       -- host, key = nwll.determineHostType(host)
       -- if host and key then
        	nw.createMeta(self.keys["referer.host"], host)
        	-- nw.logInfo("HOST:  " .. host)
        --end
    end
    
    --[[
    if directory then
        nw.createMeta(self.keys["referer.dir"], directory)
        -- nw.logInfo("DIRECTORY:  " .. directory)
    end
    if filename then
        nw.createMeta(self.keys["referer.file"], filename)
        -- nw.logInfo("FILENAME:  " .. filename)
    end
    if extension then
        nw.createMeta(self.keys["referer.ext"], extension)
        -- nw.logInfo("EXTENSION:  " .. extension)
    end
    if querystring then
        nw.createMeta(self.keys["referer.query"], querystring)
        -- nw.logInfo("QUERYSTRING:  " .. querystring)
    end
    
    --]]
end

refererpath:setCallbacks({
    [nwlanguagekey.create("referer")] = refererpath.refererMeta,  -- this is the meta callback key
})

