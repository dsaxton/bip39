# bip39

A minimal [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonic phrase generator and validator, written in Zig.

Generates cryptographically random 12- or 24-word mnemonic phrases from the English wordlist and validates existing phrases against the BIP39 checksum specification.

## Building

Requires [Zig](https://ziglang.org/download/) 0.14.1 or later.

```
zig build
```

The binary is placed at `zig-out/bin/bip39`. The default build uses `ReleaseSmall` with symbol stripping for a compact binary.

## Usage

```
Usage: bip39 COMMAND [OPTIONS]

Commands:
  generate [12|24]   Generate a new BIP39 mnemonic with 12 or 24 words (default: 12)
  validate [WORDS]   Validate a BIP39 mnemonic phrase
  help               Show this help message
```

### Generate a 12-word mnemonic (128-bit entropy)

```
$ bip39 generate
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

### Generate a 24-word mnemonic (256-bit entropy)

```
$ bip39 generate 24
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art
```

### Validate a mnemonic phrase

```
$ bip39 validate abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
Valid BIP39 mnemonic phrase.
```

Exits with code 0 on valid input and code 1 on invalid input, making it suitable for scripting.

## How it works

BIP39 defines a procedure for turning random bytes into a human-readable mnemonic:

1. Generate 128 or 256 bits of cryptographic entropy
2. Compute a SHA-256 checksum and append the first `ENT / 32` bits
3. Split the combined bitstream into 11-bit groups
4. Map each 11-bit value to a word in the 2048-word English wordlist

Validation reverses this: it decodes the words back to 11-bit indices, extracts the entropy, recomputes the SHA-256 checksum, and verifies the checksum bits match.

## Tests

```
zig build test
```

The test suite covers:

- **Wordlist integrity** -- exactly 2048 sorted, unique entries
- **Command parsing** -- all commands, null/unknown input
- **Bit extraction** -- entropy and checksum bit reading
- **Generation** -- BIP39 test vectors (all-zero, all-0xFF, 0x7F, 0x80 entropy for both 128-bit and 256-bit)
- **Validation** -- valid and invalid phrases (wrong word count, unknown words, bad checksum, empty input)
- **Round-trip** -- generated phrases pass validation for a range of entropy patterns

## License

See [LICENSE](LICENSE) if present, or consult the repository for licensing details.
