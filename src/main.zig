const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const mem = std.mem;

const WORDLIST_STR = @embedFile("english.txt");
const WORDLIST_SIZE = 2048;
const BITS_PER_WORD = 11;

const WORDLIST = blk: {
    @setEvalBranchQuota(100000);
    var words: [WORDLIST_SIZE][]const u8 = undefined;
    var i: usize = 0;
    var iter = mem.tokenizeScalar(u8, WORDLIST_STR, '\n');
    while (iter.next()) |word| : (i += 1) {
        if (i >= words.len) @compileError("Wordlist contains more than 2048 words");
        words[i] = word;
    }
    if (i != words.len) @compileError("Wordlist contains fewer than 2048 words");
    break :blk words;
};

const Command = enum {
    generate,
    validate,
    help,

    fn parse(str: ?[]const u8) Command {
        const s = str orelse return .help;
        const cmds = .{ .{ "generate", .generate }, .{ "validate", .validate }, .{ "help", .help } };
        inline for (cmds) |entry| {
            if (mem.eql(u8, s, entry[0])) return entry[1];
        }
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
    _ = args.next();

    switch (Command.parse(args.next())) {
        .generate => try handleGenerate(&args, stdout, stderr),
        .validate => try handleValidate(&args, stdout, stderr),
        .help => try printUsage(stdout),
    }
}

fn handleGenerate(args: anytype, stdout: anytype, stderr: anytype) !void {
    var entropy_len: usize = 16;

    if (args.next()) |count| {
        if (mem.eql(u8, count, "24")) {
            entropy_len = 32;
        } else if (!mem.eql(u8, count, "12")) {
            try stderr.print("Invalid word count: {s}. Defaulting to 12.\n", .{count});
        }
    }

    var entropy_buf: [32]u8 = undefined;
    const entropy = entropy_buf[0..entropy_len];
    std.crypto.random.bytes(entropy);

    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(entropy, &buf);
    try stdout.print("{s}\n", .{phrase});
}

fn handleValidate(args: anytype, stdout: anytype, stderr: anytype) !void {
    var phrase_buf: [1024]u8 = undefined;
    var pos: usize = 0;

    while (args.next()) |word| {
        if (pos > 0) {
            phrase_buf[pos] = ' ';
            pos += 1;
        }
        if (pos + word.len > phrase_buf.len) {
            try stderr.print("Input too long.\n", .{});
            return;
        }
        @memcpy(phrase_buf[pos..][0..word.len], word);
        pos += word.len;
    }

    if (pos == 0) {
        try stderr.print("No mnemonic phrase provided for validation.\n", .{});
        try printUsage(stdout);
        return;
    }

    const is_valid = validateMnemonic(phrase_buf[0..pos]);
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

fn readBit(data: []const u8, checksum: u8, pos: usize, entropy_bits: usize) u1 {
    if (pos < entropy_bits) {
        return @intCast((data[pos / 8] >> @as(u3, @intCast(7 - (pos % 8)))) & 1);
    }
    return @intCast((checksum >> @as(u3, @intCast(7 - (pos - entropy_bits)))) & 1);
}

fn getBits(data: []const u8, checksum: u8, start: usize, count: usize, entropy_bits: usize) u11 {
    var result: u11 = 0;
    for (0..count) |i| {
        result = (result << 1) | readBit(data, checksum, start + i, entropy_bits);
    }
    return result;
}

fn generateMnemonic(entropy: []const u8, buf: []u8) []const u8 {
    const entropy_bits = entropy.len * 8;
    const checksum_bits = entropy_bits / 32;
    const word_count = (entropy_bits + checksum_bits) / BITS_PER_WORD;

    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(entropy, &hash, .{});

    var pos: usize = 0;
    for (0..word_count) |i| {
        if (i > 0) {
            buf[pos] = ' ';
            pos += 1;
        }
        const index = getBits(entropy, hash[0], i * BITS_PER_WORD, BITS_PER_WORD, entropy_bits);
        const word = WORDLIST[index];
        @memcpy(buf[pos..][0..word.len], word);
        pos += word.len;
    }

    return buf[0..pos];
}

fn wordIndex(word: []const u8) ?u11 {
    var lo: usize = 0;
    var hi: usize = WORDLIST_SIZE;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const cmp = mem.order(u8, WORDLIST[mid], word);
        switch (cmp) {
            .eq => return @intCast(mid),
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return null;
}

fn validateMnemonic(mnemonic: []const u8) bool {
    var indices: [24]u11 = undefined;
    var word_count: usize = 0;

    var iter = mem.tokenizeScalar(u8, mnemonic, ' ');
    while (iter.next()) |word| {
        if (word_count >= 24) return false;
        indices[word_count] = wordIndex(word) orelse return false;
        word_count += 1;
    }

    if (word_count != 12 and word_count != 24) return false;

    const checksum_bits = word_count / 3;
    const entropy_bits = word_count * BITS_PER_WORD - checksum_bits;
    const entropy_bytes = entropy_bits / 8;

    // Extract entropy bytes from word indices
    var entropy: [32]u8 = .{0} ** 32;
    var bit_idx: usize = 0;
    for (indices[0..word_count]) |idx| {
        for (0..BITS_PER_WORD) |j| {
            if (bit_idx >= entropy_bits) break;
            const bit: u8 = @intCast((idx >> @as(u4, @intCast(10 - j))) & 1);
            entropy[bit_idx / 8] |= bit << @as(u3, @intCast(7 - (bit_idx % 8)));
            bit_idx += 1;
        }
    }

    // Regenerate from extracted entropy and compare
    var regen_buf: [1024]u8 = undefined;
    const regenerated = generateMnemonic(entropy[0..entropy_bytes], &regen_buf);
    return mem.eql(u8, regenerated, mnemonic);
}

// ── Tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "wordlist has exactly 2048 entries" {
    try testing.expectEqual(@as(usize, 2048), WORDLIST.len);
}

test "wordlist is sorted" {
    for (0..WORDLIST.len - 1) |i| {
        const order = mem.order(u8, WORDLIST[i], WORDLIST[i + 1]);
        try testing.expect(order == .lt);
    }
}

test "wordlist has no duplicates" {
    for (0..WORDLIST.len) |i| {
        for (i + 1..WORDLIST.len) |j| {
            try testing.expect(!mem.eql(u8, WORDLIST[i], WORDLIST[j]));
        }
    }
}

test "wordlist first and last entries" {
    try testing.expectEqualStrings("abandon", WORDLIST[0]);
    try testing.expectEqualStrings("zoo", WORDLIST[2047]);
}

test "Command.parse recognizes all commands" {
    try testing.expectEqual(Command.generate, Command.parse("generate"));
    try testing.expectEqual(Command.validate, Command.parse("validate"));
    try testing.expectEqual(Command.help, Command.parse("help"));
}

test "Command.parse returns help for null" {
    try testing.expectEqual(Command.help, Command.parse(null));
}

test "Command.parse returns help for unknown input" {
    try testing.expectEqual(Command.help, Command.parse("unknown"));
    try testing.expectEqual(Command.help, Command.parse(""));
    try testing.expectEqual(Command.help, Command.parse("GENERATE"));
}

test "getBits reads correct bit sequences" {
    const data = [_]u8{ 0b10110010, 0b01001110 };
    const checksum: u8 = 0;

    try testing.expectEqual(@as(u11, 0b10110010010), getBits(&data, checksum, 0, 11, 16));
    try testing.expectEqual(@as(u11, 0b1), getBits(&data, checksum, 0, 1, 16));
    try testing.expectEqual(@as(u11, 0b0), getBits(&data, checksum, 1, 1, 16));
}

test "getBits reads checksum bits beyond entropy" {
    const data = [_]u8{0xFF};
    const checksum: u8 = 0b10100000;
    try testing.expectEqual(@as(u11, 0b1), getBits(&data, checksum, 8, 1, 8));
    try testing.expectEqual(@as(u11, 0b0), getBits(&data, checksum, 9, 1, 8));
    try testing.expectEqual(@as(u11, 0b1), getBits(&data, checksum, 10, 1, 8));
}

test "generateMnemonic with all-zero 128-bit entropy" {
    const entropy = [_]u8{0} ** 16;
    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(&entropy, &buf);
    try testing.expectEqualStrings(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        phrase,
    );
}

test "generateMnemonic with all-zero 256-bit entropy" {
    const entropy = [_]u8{0} ** 32;
    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(&entropy, &buf);
    try testing.expectEqualStrings(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        phrase,
    );
}

test "generateMnemonic with all-FF 128-bit entropy" {
    const entropy = [_]u8{0xFF} ** 16;
    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(&entropy, &buf);
    try testing.expectEqualStrings(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        phrase,
    );
}

test "generateMnemonic with all-FF 256-bit entropy" {
    const entropy = [_]u8{0xFF} ** 32;
    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(&entropy, &buf);
    try testing.expectEqualStrings(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        phrase,
    );
}

test "generateMnemonic produces 12 words for 128-bit entropy" {
    const entropy = [_]u8{0x7f} ** 16;
    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(&entropy, &buf);

    var count: usize = 0;
    var iter = mem.tokenizeScalar(u8, phrase, ' ');
    while (iter.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 12), count);
}

test "generateMnemonic produces 24 words for 256-bit entropy" {
    const entropy = [_]u8{0x7f} ** 32;
    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(&entropy, &buf);

    var count: usize = 0;
    var iter = mem.tokenizeScalar(u8, phrase, ' ');
    while (iter.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 24), count);
}

test "generateMnemonic words are all in wordlist" {
    const entropy = [_]u8{0xAB} ** 16;
    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(&entropy, &buf);

    var iter = mem.tokenizeScalar(u8, phrase, ' ');
    while (iter.next()) |word| {
        try testing.expect(wordIndex(word) != null);
    }
}

test "validateMnemonic accepts valid 12-word all-zero mnemonic" {
    const valid = validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    try testing.expect(valid);
}

test "validateMnemonic accepts valid 24-word all-zero mnemonic" {
    const valid = validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    );
    try testing.expect(valid);
}

test "validateMnemonic accepts valid 12-word all-FF mnemonic" {
    const valid = validateMnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    );
    try testing.expect(valid);
}

test "validateMnemonic accepts valid 24-word all-FF mnemonic" {
    const valid = validateMnemonic(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    );
    try testing.expect(valid);
}

test "validateMnemonic rejects wrong word count (11 words)" {
    const valid = validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    );
    try testing.expect(!valid);
}

test "validateMnemonic rejects wrong word count (13 words)" {
    const valid = validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about extra",
    );
    try testing.expect(!valid);
}

test "validateMnemonic rejects invalid words" {
    const valid = validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword",
    );
    try testing.expect(!valid);
}

test "validateMnemonic rejects bad checksum" {
    const valid = validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    );
    try testing.expect(!valid);
}

test "validateMnemonic rejects empty input" {
    const valid = validateMnemonic("");
    try testing.expect(!valid);
}

test "validateMnemonic rejects single word" {
    const valid = validateMnemonic("abandon");
    try testing.expect(!valid);
}

test "round-trip: generated mnemonic validates" {
    const test_entropies = [_][16]u8{
        [_]u8{0x00} ** 16,
        [_]u8{0xFF} ** 16,
        [_]u8{0x80} ** 16,
        [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
    };

    for (&test_entropies) |*entropy| {
        var buf: [1024]u8 = undefined;
        const phrase = generateMnemonic(entropy, &buf);
        const valid = validateMnemonic(phrase);
        try testing.expect(valid);
    }
}

test "round-trip 256-bit: generated mnemonic validates" {
    const test_entropies = [_][32]u8{
        [_]u8{0x00} ** 32,
        [_]u8{0xFF} ** 32,
        [_]u8{0x55} ** 32,
    };

    for (&test_entropies) |*entropy| {
        var buf: [1024]u8 = undefined;
        const phrase = generateMnemonic(entropy, &buf);
        const valid = validateMnemonic(phrase);
        try testing.expect(valid);
    }
}

test "BIP39 test vector: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f" {
    const entropy = [_]u8{0x7f} ** 16;
    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(&entropy, &buf);
    try testing.expectEqualStrings(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        phrase,
    );
}

test "BIP39 test vector: 80808080808080808080808080808080" {
    const entropy = [_]u8{0x80} ** 16;
    var buf: [1024]u8 = undefined;
    const phrase = generateMnemonic(&entropy, &buf);
    try testing.expectEqualStrings(
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        phrase,
    );
}

test "wordIndex finds known words" {
    try testing.expectEqual(@as(?u11, 0), wordIndex("abandon"));
    try testing.expectEqual(@as(?u11, 2047), wordIndex("zoo"));
    try testing.expectEqual(@as(?u11, null), wordIndex("notaword"));
    try testing.expectEqual(@as(?u11, null), wordIndex(""));
}

test "printUsage writes expected content" {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try printUsage(fbs.writer());
    const output = fbs.getWritten();
    try testing.expect(mem.indexOf(u8, output, "Usage: bip39") != null);
    try testing.expect(mem.indexOf(u8, output, "generate") != null);
    try testing.expect(mem.indexOf(u8, output, "validate") != null);
    try testing.expect(mem.indexOf(u8, output, "help") != null);
}
