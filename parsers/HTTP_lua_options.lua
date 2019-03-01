module("HTTP_lua_options")

-- 2017.08.03.1

function registerComponents()
    --[=[
        "Register Path Components" : default TRUE (or FALSE if "Register URL" enabled)

            IMPORTANT:  It is strongly advised to not enable both this option and
            "Register URL".

            Register directory, filename, extension, query (from the request path) and
            host (from the HOST: header) as discrete meta.

            For example,

                alias.host:  www.example.com
                directory:   /someDir/
                filename:    somefile.html
                extension:   html
                query:       ?foo=bar

            If the "Register URL" option below is enabled, then this option defaults
            to FALSE.  To register both discrete meta from the path components and
            a reconstructed url, both options must be explicitly enabled.  It is
            strongly advised not to enable both options.
    --]=]
    --return true
end

function registerUrl()
    --[=[
        "Register URL" : default FALSE

            IMPORTANT:  It is strongly advised to not enable both this option and
            "Register Path Components".

            Default behavior is to register directory, filename, extension, query
            (from the request path) and host (from the HOST: header) as discrete meta.

            This option will instead register them as a single meta value (individual keys
            will not be registered due to redundancy),

                url:  www.example.com/someDir/someFile.html?foo=bar

            Note that the registered URL is a reconstructed approximation - it may not be the
            exact URL that was 'clicked on'.
    --]=]
    return false
end

function splitQuery()
    --[=[
        "Split Query String" : default false

            Default behavior is for the entire querystring from a request to be registered as an
            single meta value:

                query: alpha=one&beta=two&gamma=three

            If this option is enabled, then each element of a querystring will be registered as
            individual meta values:

                query: alpha=one
                query: beta=two
                query: gamma=three
    --]=]
    return true
end

function useOrigIP()
    --[=[
        "Use orig_ip" : default TRUE

            Default behavior is to register values from x-forwarded-for headers and the like
            with index key "orig_ip".

            If this option is disabled, then values will be registered as following:

                hostnames      "alias.host"
                IPv4           "alias.ip"
                IPv6           "alias.ipv6"
                email address  "email"
                other          "alias.host"
    --]=]
    return true
end

function refererPath()
    --[=[
        "Referer Path" : default FALSE

            Default behavior is to register the value of a "Referer:" header as "referer" meta.

            If this option is enabled, then the host, directory, filename, extension, and querystring
            values will be broken out from Referer and registered individually.  In order to
            avoid duplication, the entire Referer value will not be registered.

            For example, given the header:

                Referer: http://www.example.com/hello/world.html?foo=bar&one=two

            If this option is disabled (default), then the following meta will be registered:

                referer:  http://www.example.com/hello/world.html?foo=bar&one=two

            If enabled, then the following meta will be registered:

                alias.host:  www.example.com
                directory:   /hello/
                filename:    world.html
                extension:   html
                query:       foo=bar&one=two

            Note that if the "Split Query String" option is also enabled then the querystring
            will instead be registered individually (see above).
    --]=]
    return false
end

function userAgent()
    --[=[
        "User-Agent Key" : default "client"

            Default behavior is to register the value of User-Agent headers with the 'client'
            index key.

            Modifying this value will cause User-Agent values to additionally be registered
            with the specified key.  If the key does not already exist it will be created - normal
            key name restrictions apply.

            Note that this will result in duplication of meta.  User-agent will be registered
            to both "client" and the specified key.
    --]=]
    return "client"
end

function respReason()
    --[=[
        "Response Code Reason" : default TRUE

            For reponse codes other than 2xx, default behavior is to register both the status
            code and reason phrase together as error meta.  For example,

                error:  404 Not Found

            Disasbling this option (setting to false) will cause only the response code to be
            registered.  For example,

                error:  404
    --]=]
    return true
end

function decompress()
    --[=[
        "Decompress" : default 0

            Decompress content-encoded HTTP responses.  Encodings gzip,
            deflate, and chunked are supported.  Enabling this provides
            visibility into such responses to other parsers.

            Decompression incurs a performance penalty which will vary
            depending upon the prevalence of compressed or encoded HTTP
            responses seen in the environment.  This can be ameliorated
            to some extent by choosing to only decompress specific content
            types.

            This is a bit-packed value representing the content types to
            decompress, where:

                1    application/*
                2    audio/*
                4    font/*
                8    image/*
                16   message/*
                32   model/*
                64   text/*
                128  video/*

            The default value of 0 means that decompression will not be
            performed for any content type, which maximizes performance.

            A value of 65 specifies that content-types "application" and
            "text" will be decompressed.  This should provide a good
            balance of visibility and performance.

            To maximize visibility, a value of 255 will enable decompression
            of all content types.

            Enabling a content-type enables all constituent sub-types.  For
            example, "application" includes "application/octet-stream",
            "application/javascript", etc.

            NOTES:

                Only valid for versions 11.0+.  This option has no effect on
                versions 10.x or older as they do not have the capability to
                decompress encoded HTTP responses.

                Has no effect on instances of compression which are not HTTP
                responses, such as compressed archive files (zip, rar, et al),
                LZMA streams, etc.
    --]=]
    return 65
end

function advanced()
    --[=[
        "Advanced Analysis" : default FALSE

            Perform advanced analysis of HTTP characteristics.  Analysis includes only the first
            request and first response.  Meta is registered to the key "analysis.service".
    --]=]
    return true
end

function headerCatalog()
  --[=[
    "Header Catalog" : default FALSE
    
      Registers each header from the first request and response of the session.
      
      For each header, the type of header will be registered as "http.request" (for
      request headers) or "http.response" (for response headers).
      
      For each value, the value of the header will be registered as "req.uniq" (for
      request headers) or "resp.uniq" (for response headers).
  --]=]
  return true
end

function browserprint()
  --[=[
    "Browserprint" : default FALSE
      Whether to register a "fingerprint" of the browser based upon the specific headers
      seen in the request. The format of this browserprint value is:
        Position 1 is HTTP version: 0 = HTTP/1.0, 1 = HTTP/1.1
        Remaining positions are in order that the header was seen. Only
        the below listed headers are included in the fingerprint:
          1 = accept / 2 = accept-encoding
          3 = accept-language / 4 = connection
          5 = host / 6 = user-agent
        Example "15613":
          HTTP/1.1
          HOST:
          USER-AGENT:
          ACCEPT:
          ACCEPT-LANGUAGE:
          (other headers may have appeared between those headers)
      The usefulness of this meta is not necessarily in determining "good" or "bad"
      browser fingerprints. Rather, it is more useful to look for outliers. For
      example if the majority of values are 15613 with just a few being 15361, then
      the sessions with 15361 may be worth investigation.
  --]=]
  return true
end