//  A simple file encryption and decryption tool using the XTEA implementation
//  from mbed TLS (https://tls.mbed.org).
//
//  Copyright (C) 2026, baydroid, All Rights Reserved
//  SPDX-License-Identifier: Apache-2.0
//
//  Licensed under the Apache License, Version 2.0 (the "License"); you may
//  not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.



const std               = @import("std");
const Allocator         = std.mem.Allocator;
const Io                = std.Io;
const b64Encoder        = std.base64.standard.Encoder;
const b64Decoder        = std.base64.standard.Decoder;

const common            = @import("./common.zig");
const crash             = common.crash;
const mn                = @import("./main.zig");
const io                = mn.io;
const Console           = @import("./console.zig");
const PromptedInput     = Console.PromptedInput;
const print             = Console.print;
const nextStringLen     = Console.nextStringLen;
const nextString        = Console.nextString;
const trim              = Console.trim;
const KeywordDispatcher = Console.KeywordDispatcher;

const c = @cImport(
    {
    @cInclude("xtea.h");
    });



const maxLenDividedBy8 : u64                    = 0x8000;
var   allo             : Allocator              = undefined;
var   key16            : [16]u8                 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
var   keySet           : bool                   = false;
var   mainLoopRunning  : bool                   = true;
var   mainDispatcher   : KeywordDispatcher      = undefined;
var   xteaContext      : c.mbedtls_xtea_context = undefined;
var   timer            : std.time.Timer         = undefined;
var   rand64           : [8]u8                  = .{ 0, 0, 0, 0, 0, 0, 0, 0 };



pub fn init(a : Allocator) void
    {
    timer = std.time.Timer.start() catch crash(@src(), "");
    allo = a;
    mainDispatcher = KeywordDispatcher.init(a);
    initMainDispatcher();
    }

pub fn deinit() void
    {
    mainDispatcher.deinit();
    }

pub fn mainLoop() void
    {
    c.mbedtls_xtea_init(&xteaContext);
    defer c.mbedtls_xtea_free(&xteaContext);
    print("XTEA A simple file encryption/decryption utility.\nVersion {d}.{d}.{d}, type help or ? for help.\n", .{ common.magorVersion, common.minorVersion, common.bugfixVersion });
    mainLoopRunning = true;
    while (mainLoopRunning)
        {
        buildEntropy();
        var cmd : PromptedInput = Console.promptAndGet("xtea> ", 10000);
        defer Console.freePromptedGet(&cmd);
        const trimmedCmd : []const u8 = trim(cmd.input);
        if (trimmedCmd.len > 0) mainDispatcher.dispatch(trimmedCmd) catch { };
        }
    for (&key16) |*b| b.* = 0;
    }

fn buildEntropy() void
    {
    var rawDelta : u64 = timer.lap();
    if (rawDelta == 0) return;
    const delta : [*]u8 = @ptrCast(&rawDelta);
    var iDelta : usize = 0;
    var iRand64 : usize = 0;
    while (iRand64 < 8)
        {
        const newByte : u8 = delta[iDelta];
        iDelta = (iDelta + 1) % 8;
        if (newByte != 0)
            {
            rand64[iRand64] = rand64[iRand64] ^ newByte;
            iRand64 += 1;
            }
        }
    }

fn initMainDispatcher() void
    {
    mainDispatcher.register("key",     null, dispatchKey     );
    mainDispatcher.register("encrypt", null, dispatchEncrypt );
    mainDispatcher.register("decrypt", null, dispatchDecrypt );
    mainDispatcher.register("quit",    null, dispatchQuit    );
    mainDispatcher.register("x",       null, dispatchQuit    );
    mainDispatcher.register("help",    null, dispatchHelp    );
    mainDispatcher.register("?",       null, dispatchHelp    );
    }

fn dispatchKey(cmdTail : []const u8, _ : ?*anyopaque) void
    {
    const keyLen = nextStringLen(cmdTail);
    if (keyLen == 0)
        {
        for (&key16) |*b| b.* = 0;
        keySet = false;
        print("Key cleared.\n", .{ });
        return;
        }
    const keyBuffer : []u8 = allo.alloc(u8, keyLen) catch crash(@src(), "");
    defer
        {
        for (keyBuffer) |*b| b.* = 0;
        allo.free(keyBuffer);
        }
    var keyText : []u8 = undefined;
    _ = nextString(cmdTail, keyBuffer, &keyText);
    if (keyText.len == 0)
        {
        print("ERROR: Zero length key.\n", .{ });
        keySet = false;
        return;
        }
    makeKey16(keyText);
    c.mbedtls_xtea_setup(&xteaContext, &key16[0]);
    keySet = true;
    print("Key set.\n", .{ });
    }

fn makeKey16(keyText : []u8) void
    {
    var i : usize = 0;
    var j : usize = 0;
    while (i < 16)
        {
        key16[i] = keyText[j];
        i += 1;
        j = (j + 1) % keyText.len;
        }
    }

fn dispatchEncrypt(cmdTail : []const u8, _ : ?*anyopaque) void
    {
    if (!keySet)
        {
        print("ERROR: Key not set.\n", .{ });
        return;
        }
    const outputFilenameLen : usize = nextStringLen(cmdTail);
    if (outputFilenameLen == 0)
        {
        print("ERROR: No output file to store the encrypted text.\n", .{ });
        return;
        }
    const outputFilenameBuffer : []u8 = allo.alloc(u8, outputFilenameLen) catch crash(@src(), "");
    defer allo.free(outputFilenameBuffer);
    var outputFilename : []u8 = outputFilenameBuffer;
    _ = nextString(cmdTail, outputFilenameBuffer, &outputFilename);
    const outputFile : Io.File = Io.Dir.cwd().createFile(io, outputFilename, .{ .truncate = true, }) catch |e|
        {
        print("ERROR: Unable to open {s} for writing ({any}).\n", .{ outputFilename, e });
        return;
        };
    defer outputFile.close(io);
    print("Enter the text to be encrypted ending with Ctrl-G followed by enter.\n", .{});
    print("The maximum length allowed is {d} bytes.\n", .{ 8*maxLenDividedBy8 });
    const inputBuffer : []u8 = allo.alloc(u8, 8*maxLenDividedBy8) catch crash(@src(), "");
    defer
        {
        for (inputBuffer) |*b| b.* = 0;
        allo.free(inputBuffer);
        }
    const rawInput : []u8 = Console.readStdIn(inputBuffer, 0x07);
    buildEntropy();
    const input : []u8 = inputBuffer[0..(rawInput.len + ((8 - (rawInput.len % 8)) % 8))];
    for (rawInput.len..input.len) |i| inputBuffer[i] = 0x20;
    const outputBuffer : []u8 = allo.alloc(u8, input.len + 8) catch crash(@src(), "");
    defer
        {
        for (outputBuffer) |*b| b.* = 0;
        allo.free(outputBuffer);
        }
    if (c.mbedtls_xtea_crypt_cbc(&xteaContext, c.MBEDTLS_XTEA_ENCRYPT, input.len, &rand64[0], input.ptr, outputBuffer.ptr) != 0) crash(@src(), "encryption failed");
    const b64Len : usize = b64Encoder.calcSize(outputBuffer.len);
    const b64OutputBuffer : []u8 = allo.alloc(u8, b64Len) catch crash(@src(), "");
    defer
        {
        for (b64OutputBuffer) |*b| b.* = 0;
        allo.free(b64OutputBuffer);
        }
    _ = b64Encoder.encode(b64OutputBuffer, outputBuffer);
    var i : usize = 0;
    var delta : usize = 0;
    while (i + 80 <= b64OutputBuffer.len)
        {
        writePositionalAll(outputFilename, outputFile, b64OutputBuffer[i..(i + 80)], i + delta);
        i += 80;
        writePositionalAll(outputFilename, outputFile, "\r\n", i + delta);
        delta += 2;
        }
    if (i < b64OutputBuffer.len)
        {
        writePositionalAll(outputFilename, outputFile, b64OutputBuffer[i..], i + delta);
        writePositionalAll(outputFilename, outputFile, "\r\n", b64OutputBuffer.len + delta);
        }
    print("{d} bytes encrypted to {s}.\n", .{ input.len, outputFilename });
    }

fn writePositionalAll(outputFilename : []u8, outputFile : Io.File, buffer : []const u8, offset : u64) void
    {
    outputFile.writePositionalAll(io, buffer, offset) catch |e|
        {
        print("ERROR: Unable to write to {s} ({any}).\n", .{ outputFilename, e });
        return;
        };
    }

fn dispatchDecrypt(cmdTail : []const u8, _ : ?*anyopaque) void
    {
    if (!keySet)
        {
        print("ERROR: Key not set.\n", .{ });
        return;
        }
    const inputFilenameLen : usize = nextStringLen(cmdTail);
    if (inputFilenameLen == 0)
        {
        print("ERROR: No input file of encrypted text.\n", .{ });
        return;
        }
    const inputFilenameBuffer : []u8 = allo.alloc(u8, inputFilenameLen) catch crash(@src(), "");
    defer allo.free(inputFilenameBuffer);
    var inputFilename : []u8 = inputFilenameBuffer;
    _ = nextString(cmdTail, inputFilenameBuffer, &inputFilename);
    const inputFile : Io.File = Io.Dir.cwd().openFile(io, inputFilename, .{ .mode = Io.File.OpenMode.read_only }) catch |e|
        {
        print("ERROR: Unable to open {s} for reading ({any}).\n", .{ inputFilename, e });
        return;
        };
    defer inputFile.close(io);
    const rawLen : u64 = inputFile.length(io) catch |e|
        {
        print("ERROR: Unable to open {s} for reading ({any}).\n", .{ inputFilename, e });
        return;
        };
    const rawInputBuffer : []u8 = allo.alloc(u8, rawLen) catch crash(@src(), "");
    defer
        {
        for (rawInputBuffer) |*b| b.* = 0;
        allo.free(rawInputBuffer);
        }
    _ = inputFile.readPositionalAll(io, rawInputBuffer, 0) catch |e|
        {
        print("ERROR: Unable to read from {s} ({any}).\n", .{ inputFilename, e });
        return;
        };
    const b64InputBuffer : []u8 = rawInputBuffer[0..removeLineEndings(rawInputBuffer)];
    const len : usize = b64Decoder.calcSizeForSlice(b64InputBuffer) catch crash(@src(), "");
    if ((len % 8) != 0)
        {
        print("ERROR: After bas64 decoding the length is not a multiple of 8.\n", .{ });
        return;
        }
    if (len == 0 or len == 8)
        {
        print("\n", .{ });
        return;
        }
    const inputBuffer : []u8 = allo.alloc(u8, len) catch crash(@src(), "");
    defer
        {
        for (inputBuffer) |*b| b.* = 0;
        allo.free(inputBuffer);
        }
    b64Decoder.decode(inputBuffer, b64InputBuffer) catch crash(@src(), "");
    const outputBuffer : []u8 = allo.alloc(u8, len - 8) catch crash(@src(), "");
    defer
        {
        for (outputBuffer) |*b| b.* = 0;
        allo.free(outputBuffer);
        }
    var iv : [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    if (c.mbedtls_xtea_crypt_cbc(&xteaContext, c.MBEDTLS_XTEA_DECRYPT, len, &iv[0], inputBuffer.ptr, outputBuffer.ptr) != 0) crash(@src(), "decryption failed");
    print("{d} bytes decrypted from {s}.\n{s}\n", .{ outputBuffer.len, inputFilename, outputBuffer });
    }

fn removeLineEndings(input : []u8) usize
    {
    var iFrom : usize = 0;
    var iTo : usize = 0;
    while (iFrom < input.len)
        {
        if (input[iFrom] != '\r' and input[iFrom] != '\n')
            {
            input[iTo] = input[iFrom];
            iTo += 1;
            }
        iFrom += 1;
        }
    return iTo;
    }

fn dispatchHelp(_ : []const u8, _ : ?*anyopaque) void
    {
    const text =
        \\XTEA version {d}.{d}.{d}
        \\
        \\All connands can be abrieviated to their minimum unique length.
        \\The following commands are available.
        \\
        \\key keytext
        \\  The keytext is used for all subsequent encryption and decryption operations.
        \\  The key command without any keytext clears the current key.
        \\
        \\encrypt filename
        \\  Text typed into the terminal is encrypted and written to the named file.
        \\
        \\decrypt filename
        \\  Text in the named file is decrypted and written to the terminal.
        \\
        \\quit or x
        \\  Quit the program.
        \\
        \\help or ?
        \\  Show this help.
        \\
        \\Keytext and filename parameters may be entered as is, or as quoted strings.
        \\Quoted strings can use either " or ', and can escape ", ', or \ with a \.
        \\
        ;
    print(text, .{ common.magorVersion, common.minorVersion, common.bugfixVersion });
    }

fn dispatchQuit(_ : []const u8, _ : ?*anyopaque) void
    {
    mainLoopRunning = false;
    }
