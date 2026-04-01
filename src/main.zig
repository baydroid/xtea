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



const std     = @import("std");
const Io      = std.Io;

const Console = @import("./console.zig");
const cli     = @import("./cli.zig");

var       ioContext : Io.Threaded = .init_single_threaded;
pub const io        : Io          = ioContext.io();



pub fn main() !void
    {
    var gpa = std.heap.DebugAllocator(.{ .stack_trace_frames = 20 }){};
    // var gpa = std.heap.GeneralPurposeAllocator(.{ }){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    Console.init(allocator);
    defer Console.deinit();
    cli.init(allocator);
    defer cli.deinit();

    cli.mainLoop();
    }
