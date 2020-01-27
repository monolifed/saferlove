os.setlocale("", "all")

local mc = require "monocypher"
local ffi = require("ffi")

local CONFIGFILE = "settings.lua"

local config
local SECRETFILE = "privatekey.lua"
local SHAREDFILE = "publickey.h"
local NB_BLOCKS = 100000
local NB_ITERS  = 3
local BLOCK = 32
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

local SHAREDKEY_TEMPLATE =
[[
static const char *publickey = "%s";

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

local load_config = function()
	local f = io.open(CONFIGFILE, "r")
	if not f then return end
	f:close()
	config = loadfile(CONFIGFILE)()
	NB_BLOCKS = config.blocks or NB_BLOCKS
	NB_ITERS = config.iters or NB_ITERS
	SECRETFILE = config.secretfile or SECRETFILE
	SHAREDFILE = config.sharedfile or SHAREDFILE
	
	if config.salt then
		SALT = config.salt
	end
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
	
	local buffer = ffi.new("char[?]", 4 * BLOCK)
	local pass1 = buffer
	local pass2 = buffer + BLOCK
	--local pass2 = ffi.new("char[?]", BLOCK)
	local len1 = mc.readpassword("password:", pass1, BLOCK)
	local len2 = mc.readpassword("confirm:" , pass2, BLOCK)
	if len1 ~= len2 or mc.crypto_verify32(pass1, pass2) ~= 0 then
		return print("Generation error: passwords do not match")
	end

	local salt = buffer + 2 * BLOCK -- only the first 32 used but blake2b requires 64
	local ret
	if not SALT then
		ret = mc.randmemory(salt, BLOCK)
		if ret ~= BLOCK then
			return error("Generation error: not enough random")
		end
	else
		mc.crypto_blake2b(salt, SALT, #SALT); 
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

local generate_shared = function(filename, secretfile)
	local f = io.open(secretfile, "r")
	if not f then return error("File does not exist") end
	f:close()
	local t = loadfile(secretfile)()
	local buffer = ffi.new("char[?]", BLOCK)
	--mc.crypto_key_exchange_public_key(buffer, fromhex(t.secret));
	mc.crypto_sign_public_key(buffer, fromhex(t.secret));

	if mc.crypto_verify32(buffer, fromhex(t.public)) ~= 0 then
		return error("Keys do no match")
	end
	
	local f = io.open(filename, "w")
	f:write(SHAREDKEY_TEMPLATE:format(tocstr(buffer, BLOCK)))
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

load_config()
generate_secret(SECRETFILE)
generate_shared(SHAREDFILE, SECRETFILE)

local load_keydata = function(filename)
	local keydata = loadfile(filename)()
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

local keydata = load_keydata(SECRETFILE)
encrypt_file_as("toast.lua_temp", "toast.lus", keydata)
