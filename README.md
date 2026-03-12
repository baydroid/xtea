## A simple file encryption and decryption tool
### It uses the XTEA implementation from mbed TLS (https://tls.mbed.org).
### It requires Zig 0.16.* or greater.

If Zig 0.16 is not yet released then use the master branch

Install Zig from https://ziglang.org/download/

Clone the this xtea repository, cd into it, and issue the command

    zig build

Run xtea

    zig-out/bin/xtea

and enter help at the xtea> prompt.

    xtea> help
