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



const std = @import("std");

pub fn build(b: *std.Build) void
    {
    const exe = b.addExecutable(
        .{
        .name = "xtea",
        .root_module = b.createModule(
            .{
            .root_source_file = b.path("src/main.zig"),
            .target = b.standardTargetOptions(.{}),
            }),
        });
    exe.root_module.addIncludePath(b.path("src"));
    exe.root_module.addCSourceFile(.{ .file = b.path("src/xtea.c") });
    b.installArtifact(exe);
    }
