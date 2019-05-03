local normalize_webpage = nw.createParser("normalize_webpage", "Normalize webpage components")

local nwll = require('nwll')

normalize_webpage:setKeys({
    nwlanguagekey.create("alias.host"),
    nwlanguagekey.create("alias.ip", nwtypes.IPv4),
    nwlanguagekey.create("directory"),
    nwlanguagekey.create("filename"),
    nwlanguagekey.create("extension"),
    nwlanguagekey.create("query"),
})


function normalize_webpage:webpageMeta(index, meta)
    local host, directory, filename, extension, querystring = nwll.extractUrlElements(meta)
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
        nw.createMeta(self.keys.query, querystring)
    end
end

normalize_webpage:setCallbacks({
    [nwlanguagekey.create("web.page")] = normalize_webpage.webpageMeta,
    [nwlanguagekey.create("url")] = normalize_webpage.webpageMeta,
})

