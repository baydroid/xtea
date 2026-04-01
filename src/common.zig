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



const std                = @import("std");
const SourceLocation     = std.builtin.SourceLocation;
const Io                 = std.Io;
const Writer             = Io.File.Writer;
const stdErr             = Io.File.stderr();



pub const magorVersion  : usize = 1;
pub const minorVersion  : usize = 1;
pub const bugfixVersion : usize = 0;



pub fn crash(sl : SourceLocation, msg : []const u8) noreturn
    {
    var errWriterBuffer = [_]u8{0} ** 1024;
    var singleThreadedIo : Io.Threaded = .init_single_threaded;
    var errWriter : Writer = stdErr.writer(singleThreadedIo.io(), &errWriterBuffer);
    var errStream : *Io.Writer = &errWriter.interface;
    const bugBanner : []const u8 =
        \\
        \\
        \\     ************************
        \\     *   XTEA Bug Report    *
        \\     ************************
        \\
        \\
        ;
    errStream.print("{s}", .{ bugBanner }) catch crash(@src(), "");
    errStream.print("Version : {d}.{d}.{d}\n", .{ magorVersion, minorVersion, bugfixVersion }) catch crash(@src(), "");
    if (msg.len > 0) errStream.print("Message : {s}\n", .{ msg }) catch crash(@src(), "");
    errStream.print("From    : {s}()\n", .{ sl.fn_name }) catch crash(@src(), "");
    errStream.print("At      : Column {d} of line {d} in {s}\n\n", .{ sl.column, sl.line, sl.file }) catch crash(@src(), "");
    errStream.flush() catch crash(@src(), "");
    @trap();
    }
