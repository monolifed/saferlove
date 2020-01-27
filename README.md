# saferlove
(not really) safer love: (mis)uses encryption to make your files unreadable

# How it works
1) run make without parameters
2) run `luajit encrypt.lua`
3) follow steps to create `privatekey.lua` and `publickey.h`
4) run `make safer.so` to create

# Warning
This doesn't provide any security. It might be good for signing but it uses public key for encryption and ships it in the module to the user. It just makes seeing the code a little harder.
