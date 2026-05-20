---
title: |
  CITS3007 Secure Coding \
  Group XX — Phase 2 Report
date: Semester 1, 2026
colorlinks: true
fontsize: 12pt
margin:
  x: 2.0cm
  y: 2.5cm
lang: en
papersize: a4
section-numbering: "1.1.1."
header-includes: |
  ```{=typst}
  #show heading: set block(below: 1.2em)
  #set list(marker: [--])
  #let blueish = rgb("#0000ff")
  #show link: set text(fill: blueish)
  #set text(historical-ligatures: false)
  #show heading.where(level: 1): set text(size: 14pt)
  #show heading.where(level: 2): set text(size: 12pt)
  ```
---

**Group XX members:**

- [Isaac How Vun Chang, 23990056, IsaacChang5612@github]
- [Oliver King, 23197683, Oliver48@github]
- [Jo Magnampo, 24167087, JoLZ18 @github]
- [Zhiyuan SuN, 24259117, Yuan-ql@github]


## Introduction

We picked **Group 40** as our target. After reading through both submissions,
Group 40 looked like the more interesting one to test — it had some unsigned
arithmetic that didn't look like it had overflow protection, while Group 30
had already covered most of the obvious edge cases (they used `fseeko`/`ftello`
and a helper that did overflow-safe bounds checks, which Group 40 was missing).

Group 40's parser is split between `bun_parse.c` (485 lines) and `main.c`.
The code is clean and pretty easy to follow, with helpers like
`validate_rle_data` and `worst_error` doing a good job of keeping things
organised. The two main areas we focused on were the u64 arithmetic in the
bounds checks (which had no overflow guards) and the section overlap checks
(which didn't include the header). Both turned out to be worth looking at.


## Assumptions and Method

### Assumptions

Everything was run on Ubuntu 20.04 x86-64 (the CITS3007 SDE).
We compiled with AddressSanitizer and UBSan:

  ```
  -std=c11 -fsanitize=address,undefined -fno-omit-frame-pointer -g -O2
  ```


Where the spec and Group 40's code disagree, we go with the spec.

For F-03, we treat the BUN header as a file section under §9.3. 
The spec lists it as the first of four file sections in §1, 
and §9.3 says no two sections may overlap with no exception for the header.

### How we tested

We went through the spec section by section and checked each requirement
against the code in `bun_parse.c`:

1. **Code review** — read through all the functions looking for unchecked
   arithmetic, missing validation, and places where the code didn't match
   what the spec said.

2. **Crafting inputs** — for anything suspicious, we figured out what values
   would trigger the issue (e.g. `UINT64_MAX - 1` for `data_offset`) and
   wrote minimal `.bun` files to hit those paths.

3. **Dynamic analysis** — ran everything under ASan and UBSan. One thing
   worth noting: unsigned integer overflow is well-defined in C (it wraps),
   so UBSan won't catch it. Our findings show up as wrong exit codes or
   wrong output rather than sanitiser crashes.

4. **Automated checks** — the `reproduce` Makefile target builds the parser,
   generates the fixtures, and prints `[PASS]` or `[FAIL]` for each finding.


## Findings

### Finding F-01

- **ID:** F-01
- **Category:** Incorrect output
- **Spec reference:** §9.5 — asset names and data must lie within their sections
- **Assumptions:** None — just the plain wording of the spec.

**Description**

The bounds check in `bun_parse_assets` adds `data_offset` and `data_size`
as plain `u64` values:

```c
// bounds check — but u64 addition can overflow
if (AssetContent.data_offset + AssetContent.data_size >
        header->data_section_size) {
    add_error(ctx, "Asset data out of bounds");
    result = worst_error(result, BUN_MALFORMED);
}
```

If `data_offset = UINT64_MAX − 1` and `data_size = 2`, the addition wraps
around to `0`. The check then becomes `0 > data_section_size`, which is
always false — so no error is recorded even though the offset is completely
out of range.

The seek for the asset preview has the same issue:

```c
// seek also overflows — lands at the wrong offset
if (fseek(ctx->file,
          header->data_section_offset + AssetContent.data_offset,
          SEEK_SET) == 0) { ... }
```

With `data_section_offset = 112` and `data_offset = UINT64_MAX − 1`, that
addition wraps to `110`, so the parser ends up seeking into the string table
and printing those bytes as the asset's data content.

The fix is to rearrange the check to use subtraction:
`data_size <= data_section_size - data_offset`, with a prior check that
`data_offset <= data_section_size` to avoid underflow.

**Expected behaviour**

The parser should see that the asset's data falls outside the data section,
flag it, and exit with status 1 (`BUN_MALFORMED`).

**Actual behaviour**

The overflow makes the bounds check always pass, so no error is flagged.
The parser then reads bytes from the string table (`0x73 0x74`, "st") as
the asset's data preview and exits with status 0 (`BUN_OK`).

**Reproduction steps**

1. Unzip Group 40's phase 1 source into the `target/` directory.

2. To run all tests at once:

   ```
   make reproduce
   ```

   Or to run F-01 on its own:

3. Build with sanitisers:

   ```
   cd target && make CFLAGS="-std=c11 -fsanitize=address,undefined \
       -fno-omit-frame-pointer -g -O2" all
   cp target/bun_parser ./bun_parser_asan
   ```

4. Generate the fixture:

   ```
   python3 gen_fixtures.py
   ```

5. Run:

   ```
   ./bun_parser_asan tests/fixtures/f01_data_overflow.bun
   echo "Exit: $?"
   ```

**Expected outcome:** exit status 1 (`BUN_MALFORMED`)

**Actual outcome (observed):**

```
------------ BUN Header ------------
...
------------ Asset 0 ------------
Name:                test
...
Preview (Hex):       73 74
Preview (ASCII):     st

Exit: 0
```

The parser exits 0 (`BUN_OK`) and shows string-table bytes as the asset data.


---

### Finding F-02

- **ID:** F-02
- **Category:** Incorrect output
- **Spec reference:** §5.1 note 4 — if actual uncompressed size differs from `uncompressed_size`, return `BUN_MALFORMED`
- **Assumptions:** None.

**Description**

Spec §5.1 note 4 says the parser must return `BUN_MALFORMED` when the actual
uncompressed size doesn't match what's in the header. Group 40 does catch
the mismatch in `validate_rle_data`:

```c
// mismatch detected — returns BUN_ERR_CORRUPT (value 7)
if (total_expanded != r->uncompressed_size) {
    add_error(ctx, "RLE expanded size mismatch");
    fseek(ctx->file, saved_pos, SEEK_SET);
    result = worst_error(result, BUN_ERR_CORRUPT);
}
```

The problem is in `worst_error`, which maps `BUN_ERR_CORRUPT` to `BUN_ERR_IO`
instead of leaving it to bubble up as `BUN_MALFORMED`:

```c
// bug: BUN_ERR_CORRUPT gets turned into BUN_ERR_IO
if (incoming == BUN_ERR_CORRUPT || current == BUN_ERR_CORRUPT) {
    return BUN_ERR_IO;
}
```

So the mismatch is caught, the error message is printed, but the exit code
ends up as 3 (`BUN_ERR_IO`) rather than 1 (`BUN_MALFORMED`).

**Expected behaviour**

When the RLE expansion (8 bytes) doesn't match `uncompressed_size` (99),
the parser should exit with status 1 (`BUN_MALFORMED`) per §5.1 note 4.

**Actual behaviour**

The parser prints "RLE expanded size mismatch" correctly, but then exits
with status 3 (`BUN_ERR_IO`) — the wrong code entirely.

**Reproduction steps**

1. Build and generate fixtures as in F-01 steps 3–4.

2. Run:

   ```
   ./bun_parser_asan tests/fixtures/f02_rle_mismatch.bun
   echo "Exit: $?"
   ```

**Expected outcome:** exit status 1 (`BUN_MALFORMED`)

**Actual outcome (observed):**

```
RLE expanded size mismatch
Exit with status code 3 (BUN_ERR_IO)
...

Exit: 3
```

The error message is right, but the exit code is wrong.


---

### Finding F-03

- **ID:** F-03
- **Category:** Incorrect output
- **Spec reference:** §9.3 — no two sections may overlap; §1 — the header is a file section
- **Assumptions:** We treat the BUN header as a file section under §9.3. The
  spec introduces it as the first of four file sections in §1, and §9.3
  doesn't make any exception for it.

**Description**

Spec §9.3 says no two file sections may overlap. Group 40 checks three pairs
of sections, but never checks any of them against the header (bytes 0–59):

```c
// three overlap checks — the header [0, 60) is never compared
if (assetTableEnd > stringTableStart && assetTableStart < stringTableEnd) { ... }
if (assetTableEnd > dataTableStart   && assetTableStart < dataTableEnd)   { ... }
if (stringTableEnd > dataTableStart  && stringTableStart < dataTableEnd)  { ... }
```

Setting `data_section_offset = 0` places the data section at `[0, 8)`, which
sits inside the header at `[0, 60)`. None of the three checks notice this,
so validation passes fine.

When the parser goes to print the asset preview, it seeks to
`data_section_offset + data_offset = 0` and reads 8 bytes from the very
start of the file — the magic bytes — and prints those as the asset's data.

**Expected behaviour**

The parser should detect that the data section `[0, 8)` overlaps the header
`[0, 60)` and exit with status 1 (`BUN_MALFORMED`).

**Actual behaviour**

No overlap is detected. The parser accepts the file, prints the magic bytes
(`42 55 4E 30 01 00 00 00`, "BUN0....") as the asset data, and exits 0 (`BUN_OK`).

**Reproduction steps**

1. Build and generate fixtures as in F-01 steps 3–4.

2. Run:

   ```
   ./bun_parser_asan tests/fixtures/f03_header_overlap.bun
   echo "Exit: $?"
   ```

**Expected outcome:** exit status 1 (`BUN_MALFORMED`)

**Actual outcome (observed):**

```
------------ BUN Header ------------
...
Data Section Offset:  0
Data Section Size:    8

------------ Asset 0 ------------
Name:                test
...
Preview (Hex):       42 55 4E 30 01 00 00 00
Preview (ASCII):     BUN0....

Exit: 0
```

The parser exits 0 and shows the file's own magic bytes as asset data.


## Conclusion

We found three bugs in Group 40's parser, all producing incorrect output —
either the wrong exit code, wrong printed content, or both. No crashes or
sanitiser errors came up, which makes sense since the code avoids dynamic
allocation and sticks to fixed-size stack buffers.

The three findings split into two types. F-01 and F-02 are both arithmetic
issues: F-01 is a u64 overflow where `data_offset + data_size` wraps to zero,
making the bounds check always pass; F-02 is a logic bug in `worst_error`
where `BUN_ERR_CORRUPT` gets incorrectly turned into `BUN_ERR_IO`, giving
the wrong exit code whenever an RLE size mismatch is detected. F-03 is a
missing check — the overlap logic covers three section pairs but skips the
header entirely, so placing a section at offset 0 slips straight through.

Fixes: switch the bounds check to use subtraction to avoid overflow (F-01),
fix the `BUN_ERR_CORRUPT` branch in `worst_error` to return `BUN_MALFORMED`
(F-02), and add header comparisons to the overlap checks (F-03).
