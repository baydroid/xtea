### XTEA A simple encryption/decryption utility

Xtea isn't meant for encrypting large volumes of data, just small ammounts of text.
Such as online account recovery phrases, critical passwords, crypto seed phrases, etc.

The text to be encrypted must be typed or pasted into xtea itself, and when it's decrypted xtea displays the decrypted text on the terminal.
That way the plain text never has to be stored in a file on disk.
This helps prevent accidentally leaking the plain text by mistakenly leaving it accessible in a file.

The encrypted form is stored as ordinary text (base64).
So it can be included in emails, edited into text files, etc.

It uses CBC with the XTEA implementation from mbed TLS (https://tls.mbed.org), modified from 32 rounds to 64.
Because of this it also provides a simple example of using C and Zig in the same project.


### It requires Zig 0.16.* or greater

If Zig 0.16 is not yet released, then use the master branch.



### Build procedure

Install Zig from https://ziglang.org/download/

Clone this xtea repository, cd into it, and issue the command

    zig build

Run xtea

    zig-out/bin/xtea

and enter help at the xtea> prompt.

    me@colossus:/development/xtea$ zig build
    me@colossus:/development/xtea$ zig-out/bin/xtea
    XTEA A simple encryption/decryption utility.
    Version 1.1.0, type help or ? for help.
    xtea> ?
    XTEA version 1.1.0
    
    All connands can be abrieviated to their minimum unique length.
    The following commands are available.
    
    key keytext
      The keytext is used for all subsequent encryption and decryption operations.
      The key command without any keytext clears the current key.
    
    encrypt filename
      Text typed into the terminal is encrypted and written to the named file.
      The encrypted form is saved as text (base64) and so can be emailed, etc.
    
    decrypt filename
      Text in the named file is decrypted and written to the terminal.
    
    quit or x
      Quit the program.
    
    help or ?
      Show this help.
    
    Keytext and filename parameters may be entered as is, or as quoted strings.
    Quoted strings can use either " or ', and can escape ", ', or \ with a \.
    xtea>
