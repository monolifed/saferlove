local mc = require "monocypher"
local ffi = require("ffi")

local SECRETFILE = "privatekey.lua"
local HEADERFILE = "publickey.h"
local BLOCK = 32


--[[
The following can be modified:
NB_BLOCKS, NB_ITERS : see https://monocypher.org/manual/argon2i
HASHSALT = true : SALT parameter is hashed to compute the final salt
HASHSALT = nil/false: first 32 bytes of SALT are copied to the final salt
SALT evaluates to false: HASHSALT is ignored and the final salt is random
--]]

local NB_BLOCKS = 100000
local NB_ITERS  = 3
local HASHSALT
local SALT

local SECRETKEY_TEMPLATE =
[[
-- do not release/share
return {
	blocks = %i,
	iters = %i,
	salt = "%s",
	secret = "%s",
	public = "%s",
}

]]

local HEADERFILE_TEMPLATE =
[[
static const uint8_t publickey[32] = "%s";

]]

local tocstr = function(s, len)
	if type(s) == "cdata" then s = ffi.string(s, len) end
	local t = {}
	for i = 1, #s do t[i] = string.format("\\x%.2X", s:byte(i)) end
	return table.concat(t)
end

local tohex = function(s, len)
	if type(s) == "cdata" then s = ffi.string(s, len) end
	local t = {}
	for i = 1, #s do t[i] = string.format("%.2X", s:byte(i)) end
	return table.concat(t)
end

local fromhex = function(hex)
	t = {}
	for i = 1, #hex, 2 do
		table.insert(t, string.char(tonumber(hex:sub(i, i + 1), 16)))
	end
	return table.concat(t)
end

local generate_secret = function(filename)
	local f = io.open(filename, "r")
	if f then
		f:close()
		io.write("File exists. Do you want to overwrite file? yes/no: ")
		local input = io.read()
		if input ~= "yes" then
			return print(filename .. " skipped")
		end
	end
	
	local buffer = ffi.new("char[?]", 3 * BLOCK)
	local pass1 = buffer
	local pass2 = buffer + BLOCK
	--local pass2 = ffi.new("char[?]", BLOCK)
	local len1 = mc.readpassword("password:", pass1, BLOCK)
	local len2 = mc.readpassword("confirm:" , pass2, BLOCK)
	if len1 ~= len2 or mc.crypto_verify32(pass1, pass2) ~= 0 then
		return error("Generation error: passwords do not match")
	end

	local salt = buffer + 2 * BLOCK
	local ret
	if type(SALT) ~= "string" then
		ret = mc.randmemory(salt, BLOCK)
		if ret ~= BLOCK then
			return error("Generation error: not enough random")
		end
	elseif HASHSALT then
		mc.crypto_blake2b_general(salt, BLOCK, nil, 0, SALT, #SALT);
	else
		ffi.copy(salt, SALT, math.min(#SALT, 32));
	end

	local work_area = ffi.new("char[?]", NB_BLOCKS * 1024)
	mc.crypto_argon2i(pass1, BLOCK, work_area, NB_BLOCKS, NB_ITERS,
		pass2, BLOCK, salt, BLOCK); 

	--mc.crypto_key_exchange_public_key(pass2, pass1);
	mc.crypto_sign_public_key(pass2, pass1);
	
	local f = io.open(filename, "w")
	f:write(SECRETKEY_TEMPLATE:format(NB_BLOCKS, NB_ITERS,
		tohex(salt, BLOCK), tohex(pass1, BLOCK), tohex(pass2, BLOCK)))
	--mc.crypto_wipe(buffer, ffi.sizeof(buffer))
	f:close()
	print(filename .. " written")
end

local generate_header = function(filename, keydata)
	local buffer = ffi.new("char[?]", BLOCK)
	--mc.crypto_key_exchange_public_key(buffer, keydata.rawsecret);
	mc.crypto_sign_public_key(buffer, keydata.rawsecret);

	if mc.crypto_verify32(buffer, keydata.rawpublic) ~= 0 then
		return error("Keys do no match")
	end
	
	local f = io.open(filename, "w")
	f:write(HEADERFILE_TEMPLATE:format(tocstr(buffer, BLOCK)))
	--mc.crypto_wipe(buffer, ffi.sizeof(buffer))
	f:close()
	print(filename .. " written")
end

-- File Layout:
---------------
-- nonce  24
-- mac    16
-- sign   64
-- cypher ??
-- EOF

local lock = function(key, text, secret_key)
	local text_size = #text
	local buffer_size = text_size + 24 + 16 + 64
	local buffer = ffi.new("char[?]", buffer_size)
	local nonce = buffer
	local mac = buffer + 24
	local sign = buffer + 24 + 16
	local cypher = buffer + 24 + 16 + 64
	
	mc.randmemory(nonce, 24)
	ffi.copy(cypher, text, text_size)
	mc.crypto_lock(mac, cypher, key, nonce, cypher, text_size)

	mc.crypto_sign(sign, secret_key, public_key, cypher, text_size); 

	return ffi.string(buffer, buffer_size)
end

local unlock = function(key, cypher)
	local buffer_size = #cypher
	local text_size = buffer_size - 24 - 16 - 64
	local buffer = ffi.new("char[?]", buffer_size)
	ffi.copy(buffer, cypher, buffer_size)
	local nonce = buffer
	local mac   = buffer + 24
	local sign  = buffer + 24 + 16
	local text  = buffer + 24 + 16 + 64

	local ret
	ret = mc.crypto_check(sign, key, text, text_size)
	if ret ~= 0 then return error("Unlock: file is unsigned") end
	 
	ret = mc.crypto_unlock(text, key, nonce, mac, text, text_size)
	if ret ~= 0 then return error("Unlock: file is corrupt") end
	
	return ffi.string(text, text_size)
end

local load_keydata = function(filename)
	local f = io.open(filename, "r")
	if not f then return error("File does not exist") end
	f:close()
	
	local ret, err = loadfile(filename)
	if not ret then return error(err) end
	
	local keydata = ret()
	keydata.rawsecret = ffi.new("char[?]", 32)
	keydata.rawpublic = ffi.new("char[?]", 32)

	ffi.copy(keydata.rawsecret, fromhex(keydata.secret), 32)
	ffi.copy(keydata.rawpublic, fromhex(keydata.public), 32)
	return keydata
end

local encrypt_file_as = function(infilename, outfilename, keydata)
	local f

	f = io.open(infilename, "r")
	local text = f:read("a*")
	f:close()

	f = io.open(outfilename, "wb")
	f:write(lock(keydata.rawpublic, text, keydata.rawsecret))
	f:close()
end

local help = [[
"generate secret" : generates key file '%s'
"generate header" : generates header file '%s'
"generate" : generates both files
"encrypt (infile) (outfile)" : encrypts infile and writes outfile
"encrypt (listfile)" : loads lua table from listfile which is an array of {infile, outfile}
]]

local main = function(...)
	local args = {...}
	local argc = #args

	if args[1] == "generate" then
		if argc == 2 and args[2] == "secret" then
			os.setlocale("", "all")
			generate_secret(SECRETFILE)
			return
		end

		if argc == 2 and args[2] == "header" then
			local keydata = load_keydata(SECRETFILE)
			generate_header(HEADERFILE, keydata)
			return
		end

		if argc == 1 then
			os.setlocale("", "all")
			generate_secret(SECRETFILE)
			local keydata = load_keydata(SECRETFILE)
			generate_header(HEADERFILE, keydata)
			return
		end
	end

	if args[1] == "encrypt" then
		if argc == 3 then
			local keydata = load_keydata(SECRETFILE)
			encrypt_file_as(arg[2], arg[3], keydata)
			return
		end

		if argc == 2 then
			local keydata = load_keydata(SECRETFILE)
			local filelist = loadfile(args[3])()
			for k, v in ipairs(filelist) do
				encrypt_file_as(v[1], v[2], keydata)
			end
			return
		end
	end
	
	print(help:format(SECRETFILE, HEADERFILE))
end

main(...)
