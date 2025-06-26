const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

const WORDLIST_STR = @embedFile("english.txt");

const WORDLIST = blk: {
    @setEvalBranchQuota(100000);
    var words: [2048][]const u8 = undefined;
    var i: usize = 0;
    var iterator = mem.tokenizeScalar(u8, WORDLIST_STR, '\n');
    while (iterator.next()) |word| : (i += 1) {
        if (i >= words.len) {
            @compileError("Wordlist contains more than 2048 words");
        }
        words[i] = word;
    }
    if (i != words.len) {
        @compileError("Wordlist contains fewer than 2048 words");
    }
    break :blk words;
};

const ENT_128 = 16;
const ENT_256 = 32;

const Command = enum {
    generate,
    validate,
    help,

    fn parse(str: ?[]const u8) Command {
        if (str == null) return .help;
        if (mem.eql(u8, str.?, "generate")) return .generate;
        if (mem.eql(u8, str.?, "validate")) return .validate;
        if (mem.eql(u8, str.?, "help")) return .help;
        return .help;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // Skip program name

    switch (Command.parse(args.next())) {
        .generate => try handleGenerate(allocator, &args, stdout, stderr),
        .validate => try handleValidate(allocator, &args, stdout, stderr),
        .help => try printUsage(stdout),
    }
}

fn handleGenerate(allocator: mem.Allocator, args: anytype, stdout: anytype, stderr: anytype) !void {
    var word_count: u8 = 12;

    if (args.next()) |count| {
        if (mem.eql(u8, count, "24")) {
            word_count = 24;
        } else if (!mem.eql(u8, count, "12")) {
            try stderr.print("Invalid word count: {s}. Defaulting to 12.\n", .{count});
        }
    }

    const entropy_bytes: usize = if (word_count == 12)
        ENT_128
    else if (word_count == 24)
        ENT_256
    else
        return error.InvalidWordCount;

    var entropy_buffer: [ENT_256]u8 = undefined;
    const entropy = entropy_buffer[0..entropy_bytes];
    crypto.random.bytes(entropy);

    var hash: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(entropy, &hash, .{});

    const phrase = try generateMnemonic(allocator, entropy, hash[0]);
    defer allocator.free(phrase);
    try stdout.print("{s}\n", .{phrase});
}

fn handleValidate(allocator: mem.Allocator, args: anytype, stdout: anytype, stderr: anytype) !void {
    var phrase = std.ArrayList(u8).init(allocator);
    defer phrase.deinit();

    var first = true;
    while (args.next()) |word| {
        if (!first) try phrase.append(' ');
        try phrase.appendSlice(word);
        first = false;
    }

    if (phrase.items.len == 0) {
        try stderr.print("No mnemonic phrase provided for validation.\n", .{});
        try printUsage(stdout);
        return;
    }

    const is_valid = try validateMnemonic(allocator, phrase.items);
    try stdout.print("{s} BIP39 mnemonic phrase.\n", .{if (is_valid) "Valid" else "Invalid"});

    if (!is_valid) {
        std.process.exit(1);
    }
}

fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: bip39 COMMAND [OPTIONS]
        \\
        \\Commands:
        \\  generate [12|24]   Generate a new BIP39 mnemonic with 12 or 24 words (default: 12)
        \\  validate [WORDS]   Validate a BIP39 mnemonic phrase
        \\  help               Show this help message
        \\
        \\Examples:
        \\  bip39 generate
        \\  bip39 generate 24
        \\  bip39 validate word1 word2 word3 ... word12
        \\
    );
}

fn getBits(data: []const u8, checksum: u8, start: usize, cnt: usize, entropy_bits: usize) u11 {
    var result: u11 = 0;

    var i: usize = 0;
    while (i < cnt) : (i += 1) {
        const bit_pos = start + i;
        const bit = if (bit_pos < entropy_bits)
            @as(u1, @intCast((data[bit_pos / 8] >> @as(u3, @intCast(7 - (bit_pos % 8)))) & 1))
        else
            @as(u1, @intCast((checksum >> @as(u3, @intCast(7 - (bit_pos - entropy_bits)))) & 1));

        result = (result << 1) | bit;
    }

    return result;
}

fn generateMnemonic(allocator: mem.Allocator, entropy: []const u8, checksum_byte: u8) ![]u8 {
    const entropy_bits = @as(usize, entropy.len * 8);
    const checksum_bits = @as(usize, @intCast(entropy_bits / 32));
    const total_bits = entropy_bits + checksum_bits;
    const total_words = total_bits / 11;

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    for (0..total_words) |i| {
        if (i > 0) try result.append(' ');

        const index = getBits(entropy, checksum_byte, i * 11, 11, entropy_bits);
        try result.appendSlice(WORDLIST[index]);
    }

    return result.toOwnedSlice();
}

fn validateMnemonic(allocator: mem.Allocator, mnemonic: []const u8) !bool {
    var words = std.ArrayList([]const u8).init(allocator);
    defer words.deinit();

    var word_iter = mem.tokenizeScalar(u8, mnemonic, ' ');
    while (word_iter.next()) |word| {
        try words.append(word);
    }

    const word_count = words.items.len;
    if (word_count != 12 and word_count != 24) {
        return false;
    }

    const checksum_bits: usize = word_count / 3;
    const entropy_bits: usize = word_count * 11 - checksum_bits;
    const entropy_bytes: usize = entropy_bits / 8;

    var indices = try allocator.alloc(u11, word_count);
    defer allocator.free(indices);

    for (words.items, 0..) |word, i| {
        var found = false;
        for (WORDLIST, 0..) |wl_word, j| {
            if (mem.eql(u8, word, wl_word)) {
                indices[i] = @as(u11, @intCast(j));
                found = true;
                break;
            }
        }

        if (!found) return false;
    }

    var entropy = try allocator.alloc(u8, entropy_bytes);
    defer allocator.free(entropy);
    @memset(entropy, 0);

    var bit_idx: usize = 0;
    for (indices) |idx| {
        for (0..11) |j| {
            if (bit_idx >= entropy_bits) break;

            const shift = @as(u4, @intCast(10 - j));
            const bit = @as(u1, @intCast((idx >> shift) & 1));

            const byte_idx = bit_idx / 8;
            const bit_in_byte = @as(u3, @intCast(7 - (bit_idx % 8)));
            entropy[byte_idx] |= @as(u8, bit) << bit_in_byte;

            bit_idx += 1;
        }
    }

    var hash: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(entropy, &hash, .{});

    bit_idx = 0;
    var checksum_ok = true;
    outer: for (indices) |idx| {
        for (0..11) |j| {
            if (bit_idx < entropy_bits) {
                bit_idx += 1;
                continue;
            }
            if (bit_idx >= entropy_bits + checksum_bits) break :outer;

            const checksum_bit_idx = bit_idx - entropy_bits;
            const bit_in_hash = @as(u3, @intCast(7 - (checksum_bit_idx % 8)));
            const expected_bit = @as(u1, @intCast((hash[0] >> bit_in_hash) & 1));

            const shift = @as(u4, @intCast(10 - j));
            const actual_bit = @as(u1, @intCast((idx >> shift) & 1));

            if (expected_bit != actual_bit) {
                checksum_ok = false;
                break :outer;
            }

            bit_idx += 1;
        }
    }

    return checksum_ok;
}
