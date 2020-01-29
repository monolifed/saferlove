# saferlove
(not really) safer love: (mis)uses encryption to make your files unreadable

# How it works
1) run `make safer.so` to create the module
2) follow steps to create `privatekey.lua` and `publickey.h`
3) run `make encryptfiles` to encrypt files listed in `filelist.lua`
4) for release you need conf.lua, *.lus files and safer.so

# Warning
This doesn't provide any security.
It might be good for signing
but it uses the public key used for signing also for encryption.
Moreover it ships the key in the module to the user.
It just makes seeing the code a little harder.
