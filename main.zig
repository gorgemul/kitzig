const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;
var stdout_buf: [512]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
const stdout = &stdout_writer.interface;
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
const allocator = arena.allocator();
const config_file_content = @embedFile("./config.txt");

const text_yello_color = "\x1b[33m";
const text_reset_color = "\x1b[0m";

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("ERROR: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn writeClipboard(content: []const u8) !void {
    const argv = if (native_os == .linux) [_][]const u8{ "xclip", "-selection", "clipboard"} else [_][]const u8 {"pbcopy"}; // else macos
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Pipe;
    try child.spawn();
    try child.stdin.?.writeAll(content);
    child.stdin.?.close();
    child.stdin = null; // if not set to null explicitly, would cause compile error
    _ = try child.wait();
}

fn printDurationSince(start: *const std.time.Instant) !void {
    var buf: [128]u8 = undefined;
    const elapsed_seconds = (try std.time.Instant.now()).since(start.*) / std.time.ns_per_s;
    const hour = elapsed_seconds / 3600;
    const minute = (elapsed_seconds / 60) % 60;
    const second = elapsed_seconds % 60;
    const duration = try std.fmt.bufPrint(&buf, text_yello_color ++ "duration: {d} hours, {d} minutes, {d} seconds" ++ text_reset_color ++ "\n", .{hour, minute, second});
    try stdout.print("{s}", .{duration});
    try stdout.flush();
}

// if pipe is not empty then always ends with '\n'
fn drainPipe(pipe: std.fs.File) ![]const u8 {
    var array_list = std.ArrayList(u8).empty;
    var buf: [256]u8 = undefined;
    while (true) {
        const bytes_read = try pipe.read(&buf);
        if (bytes_read == 0) break;
        try array_list.appendSlice(allocator, buf[0..bytes_read]);
    }
    return array_list.items;
}

const Flag = union(enum) {
    help: bool,
    config: bool,
    config_value: [] const u8,
    timestamp: []const u8,
    number: []const u8,
    math: []const []const u8,
    ssh: []const u8,
    scp: []const []const u8,

    fn init(args: *std.process.ArgIterator) !Flag {
        std.debug.assert(args.skip()); // ignore exe name
        var has_any_args: bool = false;
        var copy_args = args.*;
        while (copy_args.next()) |arg| {
            has_any_args = true;
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help"))
                return .{ .help = true };
        }
        if (!has_any_args) return .{ .help = true };
        while (args.*.next()) |arg| {
            if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
                return .{ .config = true };
            } else if (std.mem.eql(u8, arg, "-cv") or std.mem.eql(u8, arg, "--config_value")) {
                return .{ .config_value = args.next() orelse return error.config_value_not_provide_value };
            } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--timestamp")) {
                return .{ .timestamp = args.next() orelse return error.timestamp_not_provide_value };
            } else if (std.mem.eql(u8, arg, "-ssh") or std.mem.eql(u8, arg, "--ssh")) {
                return .{ .ssh = args.next() orelse return error.ssh_not_provide_value };
            } else if (std.mem.eql(u8, arg, "-scp") or std.mem.eql(u8, arg, "--scp")) {
                var array_list = std.ArrayList([]const u8).empty;
                while (args.next()) |scp_arg| try array_list.append(allocator, scp_arg);
                switch (array_list.items.len) {
                    0 => return error.scp_not_provide_value,
                    1 => return error.scp_must_provide_at_least_two_value,
                    else => {},
                }
                return .{ .scp = array_list.items };
            } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--math")) {
                var array_list = std.ArrayList([]const u8).empty;
                while (args.next()) |scp_arg| try array_list.append(allocator, scp_arg);
                if (array_list.items.len == 0) return error.math_not_provide_value;
                return .{ .math = array_list.items };
            } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--number")) {
                return .{ .number = args.next() orelse return error.number_not_provide_value };
            }
        }
        return error.not_found_any_valid_flag;
    }
};

const Config = union(enum) {
    normal: struct {
        name: []const u8,
        value: []const u8,
    },
    server: struct {
        name: []const u8,
        username: []const u8,
        ip_addr: []const u8,
        password: []const u8,
        port: []const u8,
    },

    fn init() []const Config {
        var line_iter = std.mem.tokenizeAny(u8, config_file_content, "\r\n");
        var array_list = std.ArrayList(Config).empty;
        while (line_iter.next()) |line| {
            var tmp_iter = std.mem.tokenizeAny(u8, line, " \t");
            const first_token = tmp_iter.next() orelse continue;
            if (first_token[0] == '#') continue;
            var start_index: u64 = 0;
            const config_type = extractNextConfigToken(line, &start_index);
            if (std.mem.eql(u8, config_type, "normal")) {
                const name = extractNextConfigToken(line, &start_index);
                const value = extractNextConfigToken(line, &start_index);
                array_list.append(allocator, .{ .normal = .{ .name = name, .value = value }}) catch |err| fatal("config init fail: {}", .{err});
            } else if (std.mem.eql(u8, config_type, "server")) {
                const name = extractNextConfigToken(line, &start_index);
                const username = extractNextConfigToken(line, &start_index);
                const ip_addr = extractNextConfigToken(line, &start_index);
                var dot_count: usize = 0;
                for (ip_addr) |c| {
                    if (c == '.') dot_count += 1;
                }
                if (dot_count != 3) fatal("'{s}' ip_addr[{s}] invalid format", .{line, ip_addr});
                const password = extractNextConfigToken(line, &start_index);
                const port = extractNextConfigToken(line, &start_index);
                const port_number = std.fmt.parseInt(i64, port, 10) catch fatal("'{s}' port[{s}] invalid format", .{line, port});
                if (port_number < 0 or port_number > 65535) fatal("'{s}' port[{d}] invalid range, should be [0,65535]", .{line, port_number});
                array_list.append(allocator, .{ .server = .{
                    .name = name,
                    .username = username,
                    .ip_addr = ip_addr,
                    .password = password,
                    .port = port,
                }}) catch |err| fatal("config init fail: {}", .{err});
            }
        }
        return array_list.items;
    }

    fn extractNextConfigToken(line: []const u8, start_index: *u64) []const u8 {
        const open_bracket_offset = std.mem.findScalar(u8, line[start_index.*..], '[') orelse fatal("invalid format: '{s}' could not found open bracket", .{line});
        const close_bracket_offset = std.mem.findScalar(u8, line[start_index.*..], ']') orelse fatal("invalid format: '{s}' could not found close bracket", .{line});
        if (open_bracket_offset >= close_bracket_offset or close_bracket_offset - open_bracket_offset == 1)
            fatal("invalid format: '{s}'", .{line});
        defer start_index.* += close_bracket_offset + 1;
        return line[start_index.* + open_bracket_offset + 1..start_index.* + close_bracket_offset];
    }

    pub fn getOneByName(configs: []const Config, name: []const u8) ?*const Config {
        for (configs) |*config| switch (config.*) {
            .normal => if (std.mem.eql(u8, config.normal.name, name)) return config,
            .server => if (std.mem.eql(u8, config.server.name, name)) return config,
        } else return null;
    }
};

fn run(flag: *const Flag, configs: []const Config) !void {
    switch (flag.*) {
        .help => {
            try stdout.print("OPTIONS:\n", .{});
            try stdout.print("    -h,   --help,        show this help message\n", .{});
            try stdout.print("    -c,   --config       show exist configuration\n", .{});
            try stdout.print("    -cv,  --config_vlaue get config value by [config-name]\n", .{});
            try stdout.print("    -t,   --timestamp    1757651421 -> 2025-09-12 12:30:21, vice versa\n", .{});
            try stdout.print("    -n,   --number       decimal, binary(0b or 0B prefix), hex(0x or 0X prefix) transfer to one another\n", .{});
            try stdout.print("    -m,   --math         wrapper caulucator above bc, in zsh when use multiply('*') need to be quoted, so support replace 'x' for '*', 2x3 <==> 2*3 \n", .{});
            try stdout.print("    -ssh, --ssh          kit -ssh [config-name]\n", .{});
            try stdout.print("    -scp, --scp          kit -scp <foo_dir> <bar_dir> [config-name]\n", .{});
            try stdout.flush();
        },
        .config => {
            var normal_configs = std.ArrayList(Config).empty;
            var server_configs = std.ArrayList(Config).empty;
            for (configs) |config| switch (config) {
                .normal => try normal_configs.append(allocator, config),
                .server => try server_configs.append(allocator, config),
            };
            if (normal_configs.items.len == 0 and server_configs.items.len == 0) {
                try stdout.print("null\n", .{});
                try stdout.flush();
                return;
            }
            if (normal_configs.items.len > 0) {
                try stdout.print("normal\n", .{});
                for (normal_configs.items) |config| try stdout.print("  - {s}\n", .{config.normal.name});
            }
            if (server_configs.items.len > 0) {
                try stdout.print("server\n", .{});
                for (server_configs.items) |config| try stdout.print("  - {s}\n", .{config.server.name});
            }
            try stdout.flush();
        },
        .config_value => |arg| {
            const config = Config.getOneByName(configs, arg) orelse fatal("could not find config name: {s}", .{arg});
            const value = switch (config.*) {
                .normal => config.*.normal.value,
                .server => config.*.server.password,
            };
            try writeClipboard(value);
            try stdout.print("{s}\n", .{value});
            try stdout.flush();
        },
        // TODO: adapt macos
        .timestamp => |arg| {
            const arg_len = arg.len;
            var timestamp: ?u64 = std.fmt.parseInt(u64, arg, 10) catch null;
            var array_list = std.ArrayList([]const u8).empty;
            switch (native_os) {
                .linux => {
                    try array_list.append(allocator, "date");
                    try array_list.append(allocator, "-d");
                    if (timestamp) |*value| {
                        switch (arg_len) {
                            10 => {},
                            13 => value.* /= 1000, // may pass millisecond
                            else => return error.timestamp_invalid_format_length_must_be_10_or_13,
                        }
                        var buf: [16]u8 = undefined;
                        const timestamp_str = try std.fmt.bufPrint(&buf, "@{d}", .{value.*});
                        try array_list.append(allocator, timestamp_str);
                        try array_list.append(allocator, "+%Y-%m-%d %H:%M:%S");
                    } else {
                        try array_list.append(allocator, arg);
                        try array_list.append(allocator, "+%s");
                    }
                },
                else => fatal("currently not support", .{}),
            }
            var child = std.process.Child.init(array_list.items, allocator);
            child.stdout_behavior = .Pipe;
            try child.spawn();
            const result = try drainPipe(child.stdout.?);
            child.stdout.?.close();
            child.stdout = null; // if not set to null explicitly, would cause compile error
            try stdout.print("{s}", .{result});
            try stdout.flush();
            _ = try child.wait();
            try writeClipboard(result[0..result.len-1]);
        },
        .ssh => |arg| {
            const config = Config.getOneByName(configs, arg) orelse fatal("could not found ssh name: {s}", .{arg});
            switch (config.*) {
                .normal => fatal("could not found ssh config name: {s}", .{arg}),
                .server => {},
            }
            const server = config.*.server;
            const username_and_ip = try allocator.alloc(u8, server.username.len + server.ip_addr.len + 1); // 1 for @
            _ = try std.fmt.bufPrint(username_and_ip, "{s}@{s}", .{server.username, server.ip_addr});
            var array_list = std.ArrayList([]const u8).empty;
            try array_list.append(allocator, "ssh");
            try array_list.append(allocator, "-p");
            try array_list.append(allocator, server.port);
            try array_list.append(allocator, username_and_ip);
            try writeClipboard(server.password);
            var child = std.process.Child.init(array_list.items, allocator);
            const start = try std.time.Instant.now();
            _ = try child.spawnAndWait();
            try printDurationSince(&start);
        },
        .scp => |args| {
            const config_name = args[args.len-1];
            const config = Config.getOneByName(configs, config_name) orelse fatal("could not found scp name: {s}", .{config_name});
            switch (config.*) {
                .normal => fatal("could not found scp config name: {s}", .{config_name}),
                .server => {},
            }
            const server = config.*.server;
            const username_and_ip_with_home_dir = try allocator.alloc(u8, server.username.len + server.ip_addr.len + 3); // 3 for "@:~"
            _ = try std.fmt.bufPrint(username_and_ip_with_home_dir, "{s}@{s}:~", .{server.username, server.ip_addr});
            var array_list = std.ArrayList([]const u8).empty;
            try array_list.append(allocator, "scp");
            try array_list.append(allocator, "-P");
            try array_list.append(allocator, server.port);
            try array_list.append(allocator, "-r");
            var i: usize = 0;
            while (i < args.len - 1) : (i += 1) try array_list.append(allocator, args[i]);
            try array_list.append(allocator, username_and_ip_with_home_dir);
            try writeClipboard(server.password);
            var child = std.process.Child.init(array_list.items, allocator);
            const start = try std.time.Instant.now();
            _ = try child.spawnAndWait();
            try printDurationSince(&start);
        },
        .math => |args| {
            var array_list = std.ArrayList(u8).empty;
            try array_list.appendSlice(allocator, "scale=6;");
            for (args) |arg| try array_list.appendSlice(allocator, arg);
            try array_list.append(allocator, '\n');
            for (array_list.items) |*char| {
                if (char.* == 'x' or char.* == 'X') char.* = '*';
            }
            var child = std.process.Child.init(&[_][]const u8{"bc"}, allocator);
            child.stdout_behavior = .Pipe;
            child.stdin_behavior = .Pipe;
            try child.spawn();
            try child.stdin.?.writeAll(array_list.items);
            child.stdin.?.close();
            child.stdin = null;
            const result = try drainPipe(child.stdout.?);
            child.stdout.?.close();
            child.stdout = null; // if not set to null explicitly, would cause compile error
            try stdout.print("{s}", .{result});
            try stdout.flush();
            _ = try child.wait();
            try writeClipboard(result[0..result.len-1]); // last char is \n
        },
        .number => |arg| {
            const is_neg = arg[0] == '-';
            const num: []const u8 = if (is_neg) arg[1..] else arg;
            var decimal: i64 = undefined;
            if (std.mem.startsWith(u8, num, "0x") or std.mem.startsWith(u8, num, "0X")) { // hex
                decimal = try std.fmt.parseInt(i64, num[2..], 16);
            } else if (std.mem.startsWith(u8, num, "0b") or std.mem.startsWith(u8, num, "0B")) { // binary
                decimal = try std.fmt.parseInt(i64, num[2..], 2);
            } else { // decimal
                decimal = try std.fmt.parseInt(i64, num, 10);
            }
            const binary_len = std.fmt.count("{b}", .{decimal});
            if (is_neg) decimal = -decimal;
            try stdout.print("decimal: {d}\n", .{decimal});
            try stdout.print("binary : {b} (length: {d})\n", .{decimal, binary_len});
            try stdout.print("hex    : {x}\n", .{decimal});
            try stdout.flush();
        }
    }
}


pub fn main() !void {
    defer arena.deinit();
    switch (native_os) {
        .linux, .macos => {},
        else => fatal("currently only surpport linux and macos"),
    }
    var args = std.process.argsWithAllocator(allocator) catch |err| fatal("args iterator init fail: {}", .{err});
    const configs = Config.init();
    const flag = Flag.init(&args) catch |err| fatal("init flag fail: {}", .{err});
    run(&flag, configs) catch |err| fatal("kit executing error: {}", .{err});
}
