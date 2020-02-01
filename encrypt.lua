local mc = require "monocypher"
local ffi = require("ffi")

-- These are for interactive key generation, you should change these
local SALT1 = "saferlove salt value for secret key generation"
local SALT2 = "saferlove salt value for encryption key generation"

-- These affect key generation
-- See: https://monocypher.org/manual/argon2i
local NB_BLOCKS = 100000
local NB_ITERS  = 3

-- constants
local SECRETFILE = "privatekey.lua"
local HEADERFILE = "src/publickey.h"
local BLOCK = 32

local SECRETKEY_TEMPLATE =
[[
-- do not release/share
return {
	secret = "%s",
	public = "%s",
	encrypt = "%s",
}
]]

local HEADERFILE_TEMPLATE =
[[
static const uint8_t publickey[]  = "%s";
static const uint8_t encryptkey[] = "%s";
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

-- same inputs === same outputs (i.e. no randomness)
local generate_interactive = function()
	local f = io.open(SECRETFILE, "r")
	if f then
		f:close()
		io.write("Do you want to overwrite the file? yes/no: ")
		if io.read() ~= "yes" then
			return print(SECRETFILE .. " skipped")
		end
	end
	
	local buffer_size = 4 * BLOCK
	local buffer = ffi.new("char[?]", buffer_size)
	local secret  = buffer + 0 * BLOCK
	local public  = buffer + 1 * BLOCK
	local encrypt = buffer + 2 * BLOCK
	local salt    = buffer + 3 * BLOCK
	
	local work_area = ffi.new("char[?]", NB_BLOCKS * 1024)
	
	local len1 = mc.readpassword("password:", secret , BLOCK)
	local len2 = mc.readpassword("confirm:" , encrypt, BLOCK)
	if len1 ~= len2 or mc.crypto_verify32(secret, encrypt) ~= 0 then
		return error("generate_interactive: passwords do not match")
	end
	
	-- secret key / public key
	mc.crypto_blake2b_general(salt, BLOCK, nil, 0, SALT1, #SALT1);
	mc.crypto_argon2i(secret, BLOCK, work_area, NB_BLOCKS, NB_ITERS,
		secret, len1, salt, BLOCK); 
	mc.crypto_sign_public_key(public, secret);
	
	-- encryption key
	mc.crypto_blake2b_general(salt, BLOCK, nil, 0, SALT2, #SALT2);
	mc.crypto_blake2b_general(encrypt, BLOCK, nil, 0, encrypt, len2);
	mc.crypto_argon2i(encrypt, BLOCK, work_area, NB_BLOCKS, NB_ITERS,
		encrypt, BLOCK, salt, BLOCK); 
	
	local f = io.open(SECRETFILE, "w")
	f:write(SECRETKEY_TEMPLATE:format(tohex(secret, BLOCK),
		tohex(public, BLOCK), tohex(encrypt, BLOCK)))
	mc.crypto_wipe(buffer, buffer_size)
	f:close()
	print(SECRETFILE .. " written")
end

local generate_secret = function()
	local f = io.open(SECRETFILE, "r")
	if f then
		f:close()
		return print(SECRETFILE .. " skipped")
	end
	
	local buffer_size = 4 * BLOCK
	local buffer = ffi.new("char[?]", buffer_size)
	local secret  = buffer + 0 * BLOCK
	local public  = buffer + 1 * BLOCK
	local encrypt = buffer + 2 * BLOCK
	local salt    = buffer + 3 * BLOCK
	
	local work_area = ffi.new("char[?]", NB_BLOCKS * 1024)
	
	-- secret key / public key
	if  mc.randmemory(salt, BLOCK) ~= BLOCK or
		mc.randmemory(secret, BLOCK) ~= BLOCK then
		return error("generate_secret: not enough random")
	end
	mc.crypto_argon2i(secret, BLOCK, work_area, NB_BLOCKS, NB_ITERS,
		secret, BLOCK, salt, BLOCK); 
	mc.crypto_sign_public_key(public, secret);
	
	-- encryption key
	if  mc.randmemory(salt, BLOCK) ~= BLOCK or
		mc.randmemory(encrypt, BLOCK) ~= BLOCK then
		return error("generate_secret: not enough random")
	end
	mc.crypto_argon2i(encrypt, BLOCK, work_area, NB_BLOCKS, NB_ITERS,
		encrypt, BLOCK, salt, BLOCK); 
	
	local f = io.open(SECRETFILE, "w")
	f:write(SECRETKEY_TEMPLATE:format(tohex(secret, BLOCK),
		tohex(public, BLOCK), tohex(encrypt, BLOCK)))
	mc.crypto_wipe(buffer, buffer_size)
	f:close()
	print(SECRETFILE .. " written")
end

local generate_header = function(keydata)
	local buffer = ffi.new("char[?]", BLOCK)
	mc.crypto_sign_public_key(buffer, keydata.secret);

	if mc.crypto_verify32(buffer, keydata.public) ~= 0 then
		return error("Keys do no match")
	end
	
	local f = io.open(HEADERFILE, "w")
	f:write(HEADERFILE_TEMPLATE:format(
		tocstr(keydata.public, BLOCK), tocstr(keydata.encrypt, BLOCK)))
	f:close()
	print(HEADERFILE .. " written")
end

--[[ 
File Layout:
----------------
:plain:
	nonce | 24 |
	mac   | 16 | (of encrypted part)
:encrypted: (with encryption key using nonce)
	text  | ?? |
	sign  | 64 | (of unencrypted text with secret key)
:eof:
----------------
--]]

local SZSIGN, SZNONCE, SZMAC = 64, 24, 16
local SZEXTRA = SZSIGN + SZNONCE + SZMAC

local lock = function(str, keydata)
	local text_size = #str
	local buffer_size = text_size + SZEXTRA
	local buffer = ffi.new("char[?]", buffer_size)
	local nonce = buffer
	local mac   = nonce  + SZNONCE
	local text  = mac    + SZMAC
	local sign  = text + text_size
	
	ffi.copy(text, str, text_size)
	mc.crypto_sign(sign, keydata.secret, keydata.public, text, text_size); 

	mc.randmemory(nonce, SZNONCE)
	mc.crypto_lock(mac, text, keydata.encrypt, nonce, text, text_size + SZSIGN)

	return ffi.string(buffer, buffer_size)
end

local unlock = function(str, keydata)
	local buffer_size = #str
	local text_size = buffer_size - SZEXTRA
	local buffer = ffi.new("char[?]", buffer_size)
	local nonce = buffer
	local mac   = nonce + SZNONCE
	local text  = mac   + SZMAC
	local sign  = text  + text_size
	
	ffi.copy(buffer, str, buffer_size)
	
	local ret
	
	ret = mc.crypto_unlock(text, keydata.encrypt, nonce, mac, text, text_size + SZSIGN)
	if ret ~= 0 then return error("Unlock: file is corrupt") end
	
	ret = mc.crypto_check(sign, keydata.public, text, text_size)
	if ret ~= 0 then return error("Unlock: file is unsigned") end
	 
	return ffi.string(text, text_size)
end

local load_keydata = function()
	local f = io.open(SECRETFILE, "r")
	if not f then return error("File does not exist") end
	f:close()
	
	local ret, err = loadfile(SECRETFILE)
	if not ret then return error(err) end
	
	local ret = ret()
	local keydata = {}
	keydata.buffer = ffi.new("char[?]", 3 * BLOCK)
	keydata.secret  = keydata.buffer + 0 * BLOCK
	keydata.public  = keydata.buffer + 1 * BLOCK
	keydata.encrypt = keydata.buffer + 2 * BLOCK

	ffi.copy(keydata.secret,  fromhex(ret.secret),  BLOCK)
	ffi.copy(keydata.public,  fromhex(ret.public),  BLOCK)
	ffi.copy(keydata.encrypt, fromhex(ret.encrypt), BLOCK)

	return keydata
end

local encrypt_file_as = function(infilename, outfilename, keydata)
	local f

	f = io.open(infilename, "r")
	local text = f:read("a*")
	f:close()

	f = io.open(outfilename, "wb")
	f:write(lock(text, keydata))
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

	if args[1] == "test" and argc == 1 then
		local keydata = load_keydata()
		local a = lock(help, keydata)
		local b = unlock(a, keydata)
		print(help == b)
		return
	end

	if args[1] == "generate" and argc == 2 then
		if args[2] == "secret" then
			os.setlocale("", "all")
			generate_secret()
			return
		end

		if args[2] == "interactive" then
			os.setlocale("", "all")
			generate_interactive()
			return
		end

		if args[2] == "header" then
			local keydata = load_keydata()
			generate_header(keydata)
			return
		end
	end

	if args[1] == "encrypt" then
		if argc == 3 then
			local keydata = load_keydata()
			encrypt_file_as(arg[2], arg[3], keydata)
			return
		end

		if argc == 2 then
			local keydata = load_keydata()
			local filelist = loadfile(args[2])()
			for k, v in ipairs(filelist) do
				print(("Encrypting '%s' as '%s'"):format(v[1], v[2]))
				encrypt_file_as(v[1], v[2], keydata)
			end
			return
		end
	end
	
	print(help:format(SECRETFILE, HEADERFILE))
end

main(...)
