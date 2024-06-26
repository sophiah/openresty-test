local _M = {}
local aws_cred = {}
local sha2 = require 'sha2';
local verbose = false

function _M.load_cred(key_id, secret_id)
    -- we can load more keys if needed
    aws_cred[key_id] = secret_id
end

function _M.verbose()
    verbose = true
end

local authType = "AWS4-HMAC-SHA256" -- size 16
local credentialPrefix = "Credential=" -- size 11
local signedHeadersPrefix = "SignedHeaders=" -- size 14
local signature = "Signature=" -- size 10

local function table_print(tbl)
    for name, value in pairs(tbl) do
        ngx.log(ngx.ERR, name .. " ==> " .. tostring(value) )
    end
end

local function sha256(str)
    return sha2.sha256(str)
end

local function sign(key, msg)
    return sha2.hex_to_bin(sha2.hmac(sha2.sha256, key, msg))
end

local function hmac_sha256(key, msg)
    return sha2.hmac(sha2.sha256, key, msg)
end

local function startsWith(str, start)
    return str:sub(1, #start) == start
end

local function normalized_param()
    local args = ngx.req.get_uri_args()
    local key_table = {}
    local cache_key_param = {}
    for name, value in pairs(args) do
        if name ~= "X-Amz-Signature" then
            table.insert(key_table, name)
        end
        if startsWith(string.lower(name), "x-amz-") == false then
            table.insert(cache_key_param, name)
        end
    end

    table.sort(key_table)
    table.sort(cache_key_param)
    local first = true
    local tmp_var = ""
    for _, key in ipairs(key_table) do
        if first ~= true then
            tmp_var = tmp_var .. "&"
        end
        if args[key] == nil or type(args[key]) == "boolean" then
            tmp_var = tmp_var .. key .. "=" 
        else
            tmp_var = tmp_var .. key .. "=" .. ngx.escape_uri(args[key])
        end
        first = false
    end

    local first = true
    local cache_key = ""
    for _, key in ipairs(cache_key_param) do
        if first ~= true then
            cache_key = cache_key .. "&"
        end
        if args[key] == nil or type(args[key]) == "boolean" then
            cache_key = cache_key .. key .. "=" 
        else
            cache_key = cache_key .. key .. "=" .. ngx.escape_uri(args[key])
        end
        first = false
    end

    return tmp_var, cache_key
end

local function create_signature(authInfo)
    -- calculate
    local cReq = authInfo["HTTP_METHOD"] .. "\n" .. 
                 authInfo["HTTP_RESOURCE"] .. "\n" .. 
                 authInfo["REQUEST_PARAMS"] .. "\n" .. 
                 authInfo["CanonicalHeaders"] .. "\n" .. 
                 authInfo["SignedHeaders"] .. "\n" .. 
                 authInfo["x-amz-content-sha256"];
    if (verbose) then
        ngx.log(ngx.ERR, "cReq " .. cReq)
    end
    
    local string_to_sign = "AWS4-HMAC-SHA256\n" ..
                        authInfo["x-amz-date"] .. "\n" ..
                        authInfo["access_date"] .. "/" .. authInfo["region"] .. "/" .. authInfo["service"] .. "/aws4_request\n" .. 
                        sha256(cReq);

    if verbose then
        ngx.log(ngx.ERR, "string_to_sign " .. string_to_sign)
    end
    -- signing key
    local secret = aws_cred[ authInfo["access_key_id"] ]
    local datekey = sign("AWS4" .. secret , authInfo["access_date"])
    local dateRegionKey = sign(datekey, authInfo["region"])
    local dateRegionServiceKey = sign(dateRegionKey, authInfo["service"])
    local signKey = sign(dateRegionServiceKey, "aws4_request")
   
    local signature = hmac_sha256(signKey, string_to_sign)
    if verbose then
        ngx.log(ngx.ERR, "sign compare ==> " .. authInfo["Org::Signature"] .. " ==> " .. signature)
    end
    return signature
end

local function _processCredential(str, authInfo)
    local tmp_idx = 0;
    local mnext = string.gmatch(str, "[^/]+")
    authInfo["access_key_id"] = mnext()
    authInfo["access_date"] = mnext()
    authInfo["region"] = mnext()
    authInfo["service"] = mnext()
end

local function _processSignHeaders(str, headers, authInfo)
    local cHeader = ""
    for subm in string.gmatch(str, "[^;,]+") do
        cHeader = cHeader .. string.lower(subm) .. ":" .. headers[subm] .. "\n"
    end
    authInfo["CanonicalHeaders" ] = cHeader
end

local function _processStandardHttp(authInfo)
    -- data from http requests
    authInfo["HTTP_METHOD"] = ngx.var.request_method
    local x_uri = ngx.var.request_uri
    local mnext = string.gmatch(x_uri, "[^?]+")
    local cache_key_param
    authInfo["HTTP_RESOURCE"] = mnext()

    authInfo["REQUEST_PARAMS"], cache_key_param = normalized_param()
    authInfo["CACHE_KEY"] = authInfo["HTTP_RESOURCE"] .. "?" .. cache_key_param

end

local function authWithHeaderAuth(headers)
    local authInfo = {}
    local headerAuthorization = headers["Authorization"]
    -- data from auth headers
    for match in string.gmatch(headerAuthorization, "%S+") do
        if startsWith(match, credentialPrefix) then
            local tmp = string.sub(match, 12, #match);
            _processCredential(tmp, authInfo)
        elseif startsWith(match, signedHeadersPrefix) then
            local tmp = string.sub(match, 15, #match);
            if tmp:sub(-1) == "," then
                tmp = tmp:sub(1, -2) 
            end
            authInfo["SignedHeaders"] = tmp
            _processSignHeaders(tmp, headers, authInfo)
        elseif startsWith(match, signature) then
            authInfo["Org::Signature"] = string.sub(match, 11, #match);
        end
    end
    authInfo["x-amz-date"] = headers["x-amz-date"]
    authInfo["x-amz-content-sha256"] = headers["x-amz-content-sha256"]
    _processStandardHttp(authInfo)

    -- table_print(authInfo)
    local cal_sig = create_signature(authInfo)
    if cal_sig == authInfo["Org::Signature"] then
        return true, authInfo["CACHE_KEY"]
    else
        return false, authInfo["CACHE_KEY"]
    end
end

local function authWithQParam(headers, args)
    local authInfo = {}
    authInfo["Org::Signature"] = args["X-Amz-Signature"]
    _processStandardHttp(authInfo)
    authInfo["SignedHeaders"] = args["X-Amz-SignedHeaders"] 
    _processSignHeaders(args["X-Amz-SignedHeaders"], headers, authInfo)
    _processCredential(args["X-Amz-Credential"], authInfo)
    authInfo["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
    authInfo["x-amz-date"] = args["X-Amz-Date"]

    local cal_sig = create_signature(authInfo)

    if cal_sig == authInfo["Org::Signature"] then
        return true, authInfo["CACHE_KEY"]
    else
        return false, authInfo["CACHE_KEY"]
    end
end


function _M.revalidate()
    local headers = ngx.req.get_headers()
    local args = ngx.req.get_uri_args()
    local headerAuthorization = headers["Authorization"]
    local authResult = false
    local cacheKey = ""
    if headerAuthorization ~= nil and string.sub(headerAuthorization, 1, 16) == authType then
        authResult, cacheKey = authWithHeaderAuth(headers);
    elseif args["X-Amz-Algorithm"] ~= nil and args["X-Amz-Algorithm"] == authType then 
        authResult, cacheKey = authWithQParam(headers, args)
    end

    if authResult == false then
        ngx.status = 403
        ngx.say("Forbidden while re-validate")
        ngx.exit(403)
        return ""
    else
        return cacheKey
    end

end


return _M