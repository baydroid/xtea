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



const std       = @import("std");
const Allocator = std.mem.Allocator;
const Io        = std.Io;
const File      = Io.File;
const Limit     = Io.Limit;
const stdIn     = Io.File.stdin();
const stdOut    = Io.File.stdout();
const StringHashMap = std.hash_map.StringHashMap;
const IntegerBitSet = std.bit_set.IntegerBitSet;
const Range         = std.bit_set.Range;

const common    = @import("./common.zig");
const crash     = common.crash;
const mn        = @import("./main.zig");
const io        = mn.io;



pub var logFilename     : ?[]u8           = null;

var     allocator       : ?Allocator      = null;
var     logWriter       : ?Io.File.Writer = null;
var     logFile         : File            = stdOut;
var     logWriterBuffer : [2048]u8        = undefined;

pub const PromptedInput = struct
    {
    input  : []u8,
    buffer : []u8,
    };



pub fn init(a : Allocator) void
    {
    allocator = a;
    }

pub fn deinit() void
    {
    closeLog();
    }

pub fn promptAndGet(prompt : []const u8, maxLen : usize) PromptedInput
    {
    const lineBuffer : []u8 = allocator.?.alloc(u8, maxLen) catch crash(@src(), "");
    stdPrint("{s}", .{ prompt });
    const input : []u8 = readStdIn(lineBuffer, '\n');
    logPrint("{s}{s}\n", .{ prompt, input });
    return PromptedInput
        {
        .input  = input,
        .buffer = lineBuffer,
        };
    }

pub fn freePromptedGet(pi : *PromptedInput) void
    {
    allocator.?.free(pi.buffer);
    }

pub fn readStdIn(buffer : []u8, delimiter : u8) []u8
    {
    const stdInBuffer : []u8 = allocator.?.alloc(u8, 0x10000) catch crash(@src(), "");
    defer allocator.?.free(stdInBuffer);
    var stdReader : File.Reader = stdIn.reader(io, stdInBuffer);
    const inStream : *Io.Reader = &stdReader.interface;
    var lineWriter : Io.Writer = Io.Writer.fixed(buffer);
    const lineLen : usize = inStream.streamDelimiterLimit(&lineWriter, delimiter, Limit.limited(buffer.len)) catch crash(@src(), "");
    return buffer[0..lineLen];
    }

pub fn print(comptime format : []const u8, args : anytype) void
    {
    stdPrint(format, args);
    logPrint(format, args);
    }

fn stdPrint(comptime format : []const u8, args : anytype) void
    {
    var outWriterBuffer : [2048]u8 = undefined;
    var outWriter : File.Writer = stdOut.writer(io, &outWriterBuffer);
    var outStream : *Io.Writer = &outWriter.interface;
    outStream.print(format, args) catch crash(@src(), "");
    outStream.flush() catch crash(@src(), "");
    }

fn logPrint(comptime format : []const u8, args : anytype) void
    {
    if (logFilename != null)
        {
        var logStream : *Io.Writer = &logWriter.?.interface;
        logStream.print(format, args) catch |e|
            {
            logWriteError(e);
            return;
            };
        logStream.flush() catch |e| logWriteError(e);
        }
    }

pub fn openLog(filename : []const u8, truncate : bool) void
    {
    closeLog();
    logFile = Io.Dir.cwd().createFile(io, filename, .{ .truncate = truncate, }) catch |e|
        {
        logOpenError(filename, false, e);
        return;
        };
    logWriter = logFile.writer(io, &logWriterBuffer);
    if (!truncate)
        {
        const len : u64 = logFile.length(io) catch |e|
            {
            logOpenError(filename, true, e);
            return;
            };
        if (len > 0) logWriter.?.seekTo(len) catch |e|
            {
            logOpenError(filename, true, e);
            return;
            };
        }
    logFilename = Allocator.dupe(allocator.?, u8, filename) catch crash(@src(), "");
    print("Opened log file {s}.\n", .{ logFilename.? });
    }

pub fn closeLog() void
    {
    if (logFilename) |lfn|
        {
        print("Closing log file {s}.\n", .{ lfn });
        allocator.?.free(lfn);
        logWriter.?.flush() catch {};
        logFile.close(io);
        logWriter = null;
        logFilename = null;
        }
    }

fn logWriteError(e : anyerror) void
    {
    if (logFilename) |lfn|
        {
        stdPrint("ERROR: Unable to write to log file {s} ({any}).\n", .{ lfn, e });
        closeLog();
        }
    }

fn logOpenError(filename : []const u8, closeLogFile : bool, e : anyerror) void
    {
    stdPrint("ERROR: Unable to open {s} for writing ({any}).\n", .{ filename, e });
    if (closeLogFile)
        {
        logFile.close(io);
        logWriter = null;
        logFilename = null;
        }
    }



pub const KeywordDispatcher = struct
    {
    dispatchers : StringHashMap(DispatchTarget),

    pub fn init(a : Allocator) KeywordDispatcher
        {
        return KeywordDispatcher
            {
            .dispatchers = StringHashMap(DispatchTarget).init(a),
            };
        }

    pub fn deinit(kdsp : *KeywordDispatcher) void
        {
        kdsp.dispatchers.deinit();
        }

    pub fn register(kdsp : *KeywordDispatcher, keyword : []const u8, context : ?*anyopaque, handler : *const fn(cmdTail : []const u8, context : ?*anyopaque) void) void
        {
        var gopr = kdsp.dispatchers.getOrPut(keyword) catch crash(@src(), "");
        if (gopr.found_existing)
            {
            std.debug.print("KeywordDispatcher: Keyword {s} is being registered for the 2nd time!\n", .{ keyword });
            crash(@src(), "");
            }
        DispatchTarget.initPtr(gopr.value_ptr, context, handler);
        var len : usize = keyword.len - 1;
        while (len > 0)
            {
            gopr = kdsp.dispatchers.getOrPut(keyword[0..len]) catch crash(@src(), "");
            if (gopr.found_existing)
                _ = kdsp.dispatchers.remove(keyword[0..len])
            else
                DispatchTarget.initPtr(gopr.value_ptr, context, handler);
            len -= 1;
            }
        }

    pub fn dispatch(kdsp : *KeywordDispatcher, cmd : []const u8) ParseError!void
        {
        var iKwdFloor : usize = 0;
        while (iKwdFloor < cmd.len and isSpaceCh(cmd[iKwdFloor])) iKwdFloor += 1;
        var iKwdRoof : usize = iKwdFloor;
        while (iKwdRoof < cmd.len and !isSpaceCh(cmd[iKwdRoof])) iKwdRoof += 1;
        const keyword : []const u8 = cmd[iKwdFloor..iKwdRoof];
        const dtOpt : ?*DispatchTarget = kdsp.dispatchers.getPtr(keyword);
        if (dtOpt) |dt|
            dt.dispatch(cmd[iKwdRoof..])
        else
            {
            print("ERROR: Unknown or ambiguous command word \"{s}\".\n", .{ keyword });
            return ParseError.failure;
            }
        }
    };

const DispatchTarget = struct
    {
    context : ?*anyopaque,
    handler : *const fn(cmdTail : []const u8, context : ?*anyopaque) void,

    pub fn initPtr(dt : *DispatchTarget, context : ?*anyopaque, handler : *const fn(cmdTail : []const u8, context : ?*anyopaque) void) void
        {
        dt.context = context;
        dt.handler = handler;
        }

    pub fn dispatch(dt : *DispatchTarget, cmdTail : []const u8) void
        {
        dt.handler(cmdTail, dt.context);
        }
    };

pub const OptionsReader = struct
    {
    validOptions : IntegerBitSet(256),
    foundOptions : IntegerBitSet(256),
    foundCount   : usize,
    intPermitted : bool,
    intFound     : bool,
    intEnded     : bool,
    intValue     : usize,

    pub fn init() OptionsReader
        {
        return OptionsReader
            {
            .validOptions = IntegerBitSet(256).initEmpty(),
            .foundOptions = IntegerBitSet(256).initEmpty(),
            .foundCount = 0,
            .intPermitted = false,
            .intFound = false,
            .intEnded = false,
            .intValue = 0,
            };
        }

    pub fn setValid(optr : *OptionsReader, option : u8) void
        {
        optr.validOptions.set(option);
        }

    pub fn setIntPermitted(optr : *OptionsReader) void
        {
        optr.intPermitted = true;
        }

    pub fn isSet(optr : *OptionsReader, option : u8) bool
        {
        return optr.foundOptions.isSet(option);
        }

    pub fn read(optr : *OptionsReader, cmd : []const u8) ParseError![]const u8
        {
        optr.foundCount = 0;
        optr.intFound = false;
        optr.intEnded = false;
        optr.intValue = 0;
        optr.foundOptions.setRangeValue(Range{ .start = 0, .end = 256, }, false);
        var i : usize = 0;
        while (true)
            {
            while (i < cmd.len and isSpaceCh(cmd[i])) i += 1;
            if (i >= cmd.len or cmd[i] != '-') return trim(cmd[i..]);
            i += 1;
            while (i < cmd.len and !isSpaceCh(cmd[i]))
                {
                const ch : u8 = cmd[i];
                if ('0' <= ch and ch <= '9')
                    {
                    if (!optr.intPermitted or optr.intEnded)
                        {
                        print("ERROR: Invalid option {s}.\n", .{ cmd[i..i + 1] });
                        return ParseError.failure;
                        }
                    optr.intFound = true;
                    optr.intValue = 10*optr.intValue + ch - '0';
                    }
                else
                    {
                    if (optr.intFound) optr.intEnded = true;
                    if (optr.validOptions.isSet(ch))
                        {
                        optr.foundOptions.set(ch);
                        optr.foundCount += 1;
                        }
                    else
                        {
                        print("ERROR: Invalid option {s}.\n", .{ cmd[i..i + 1] });
                        return ParseError.failure;
                        }
                    }
                i += 1;
                }
            }
        }
    };

pub const ParseError = error
    {
    failure,
    };

pub fn nextStringLen(input : []const u8) usize
    {
    if (input.len == 0) return 0;
    var iFloor : usize = 0;
    while (iFloor < input.len and isSpaceCh(input[iFloor])) iFloor += 1;
    if (iFloor >= input.len) return 0;
    switch (input[iFloor])
        {
        '\'', '"'  => { return nextQuotedStringLen(input[iFloor..]); },
        else =>
            {
            var iRoof : usize = iFloor + 1;
            while (iRoof < input.len and !isSpaceCh(input[iRoof])) iRoof += 1;
            return iRoof - iFloor;
            },
        }
    }

pub fn nextString(input : []const u8, buffer : []u8, output : *[]u8) []const u8
    {
    var iScan : usize = 0;
    while (iScan < input.len and isSpaceCh(input[iScan])) iScan += 1;
    if (iScan >= input.len)
        {
        output.* = buffer[0..0];
        return input[0..0];
        }
    switch (input[iScan])
        {
        '\'', '"' => { return nextQuotedString(input[iScan..], buffer, output); },
        else =>
            {
            var iBuffer : usize = 0;
            while (true)
                {
                if (iScan >= input.len or isSpaceCh(input[iScan]))
                    {
                    output.* = buffer[0..iBuffer];
                    return input[iScan..];
                    }
                else
                    {
                    buffer[iBuffer] = input[iScan];
                    iBuffer += 1;
                    iScan += 1;
                    }
                }
            },
        }
    }

fn nextQuotedStringLen(input : []const u8) usize
    {
    if (input.len < 3) return 0;
    var len : usize = 0;
    var afterBackslash : bool = false;
    const quote : u8 = input[0];
    var iFloor : usize = 1;
    while (iFloor < input.len)
        {
        const ch : u8 = input[iFloor];
        iFloor += 1;
        if (afterBackslash)
            {
            len += 1;
            afterBackslash = false;
            }
        else if (ch == '\\')
            afterBackslash = true
        else if (ch == quote)
            return len
        else
            len += 1;
        }
    return len;
    }

fn nextQuotedString(input : []const u8, buffer : []u8, output : *[]u8) []const u8
    {
    if (input.len < 3)
        {
        output.* = buffer[0..0];
        return input[0..0];
        }
    var afterBackslash : bool = false;
    const quote : u8 = input[0];
    var iBuffer : usize = 0;
    var iScan : usize = 1;
    while (iScan < input.len)
        {
        const ch : u8 = input[iScan];
        iScan += 1;
        if (afterBackslash)
            {
            buffer[iBuffer] = ch;
            iBuffer += 1;
            afterBackslash = false;
            }
        else if (ch == '\\')
            afterBackslash = true
        else if (ch == quote)
            break
        else
            {
            buffer[iBuffer] = ch;
            iBuffer += 1;
            }
        }
    output.* = buffer[0..iBuffer];
    return input[iScan..];
    }

pub fn isSpaceCh(ch : u8) bool
    {
    switch (ch)
        {
        ' ', '\t', '\r', '\n' => return true,
        else                  => return false,
        }
    }

pub fn trim(str : []const u8) []const u8
    {
    if (str.len == 0) return str[0..0];
    var iFloor : usize = 0;
    while (iFloor < str.len and isSpaceCh(str[iFloor])) iFloor += 1;
    if (iFloor >= str.len) return str[0..0];
    var iRoof = str.len;
    while (iRoof > 0 and isSpaceCh(str[iRoof - 1])) iRoof -= 1;
    return str[iFloor..iRoof];
    }
