"""
gen_fixtures.py — builds the crafted .bun files we use to trigger each finding.

F-01  u64 overflow lets a bad data_offset slip past the bounds check
F-02  RLE size mismatch returns the wrong exit code (3 instead of 1)
F-03  data section at offset 0 overlaps the header but nobody checks

Run:  python3 gen_fixtures.py
"""

import struct
import os

BUN_MAGIC         = 0x304E5542
VERSION_MAJOR     = 1
VERSION_MINOR     = 0
UINT64_MAX        = 0xFFFFFFFFFFFFFFFF

os.makedirs("tests/fixtures", exist_ok=True)


def pack_header(asset_count,
                asset_table_offset,
                string_table_offset, string_table_size,
                data_section_offset, data_section_size):
    """Return the 60-byte BUN header as bytes."""
    return struct.pack(
        "<IHH I QQQQQQ",
        BUN_MAGIC,
        VERSION_MAJOR, VERSION_MINOR,
        asset_count,
        asset_table_offset,
        string_table_offset, string_table_size,
        data_section_offset, data_section_size,
        0,          # reserved
    )


def pack_asset(name_offset, name_length,
               data_offset, data_size, uncompressed_size,
               compression, asset_type=0, checksum=0, flags=0):
    """Return a 48-byte BUN asset record as bytes."""
    return struct.pack(
        "<II QQQ IIII",
        name_offset, name_length,
        data_offset, data_size, uncompressed_size,
        compression, asset_type, checksum, flags,
    )


# ---------------------------------------------------------------------------
# F-01 — u64 overflow bypasses the bounds check in bun_parse_assets
# ---------------------------------------------------------------------------
# Group 40 checks:  data_offset + data_size > data_section_size
# but both sides are u64, so if data_offset is close to UINT64_MAX the
# addition wraps around to 0 and the check always passes.
#
# We use data_offset = UINT64_MAX-1 and data_size = 2, so the sum wraps
# to 0 which is obviously <= data_section_size (8) — no error is flagged.
# The seek for the preview also overflows, so the parser ends up reading
# from the string table instead and prints those bytes as "asset data".
#
# Expected: exit 1 (BUN_MALFORMED)   Actual: exit 0 (BUN_OK)
# ---------------------------------------------------------------------------

f01 = bytearray()
f01 += pack_header(
    asset_count=1,
    asset_table_offset=60,
    string_table_offset=108,  string_table_size=4,
    data_section_offset=112,  data_section_size=8,
)
f01 += pack_asset(
    name_offset=0, name_length=4,
    data_offset=UINT64_MAX - 1,   # <-- triggers overflow
    data_size=2,
    uncompressed_size=0,
    compression=0,                # uncompressed; uncompressed_size must be 0
)
f01 += b"test"      # string table  (offset 108, size 4)
f01 += b"XXXXXXXX"  # data section  (offset 112, size 8)

path = "tests/fixtures/f01_data_overflow.bun"
with open(path, "wb") as fh:
    fh.write(f01)
print(f"[+] {path}  ({len(f01)} bytes)")
assert len(f01) == 120


# ---------------------------------------------------------------------------
# F-02 — RLE size mismatch returns BUN_ERR_IO (3) instead of BUN_MALFORMED (1)
# ---------------------------------------------------------------------------
# validate_rle_data() does catch the mismatch correctly and returns
# BUN_ERR_CORRUPT, but worst_error() has a bug where BUN_ERR_CORRUPT
# silently gets turned into BUN_ERR_IO instead.  The spec says this
# case should be BUN_MALFORMED (exit 1).
#
# Our RLE data is two pairs: [03 41] [05 42] which expands to 8 bytes
# (3 × 'A' + 5 × 'B').  We set uncompressed_size to 99, so the mismatch
# (8 vs 99) gets detected — the error message is printed — but then
# the wrong exit code comes out.
#
# Expected: exit 1 (BUN_MALFORMED)   Actual: exit 3 (BUN_ERR_IO)
# ---------------------------------------------------------------------------

f02 = bytearray()
f02 += pack_header(
    asset_count=1,
    asset_table_offset=60,
    string_table_offset=108,  string_table_size=4,
    data_section_offset=112,  data_section_size=4,
)
f02 += pack_asset(
    name_offset=0, name_length=4,
    data_offset=0,
    data_size=4,              # 2 RLE pairs × 2 bytes each
    uncompressed_size=99,     # deliberate mismatch: actual expansion = 8
    compression=1,            # RLE
)
f02 += b"test"                # string table  (offset 108, size 4)
f02 += bytes([3, 0x41,        # pair 1: count=3, value='A'  → 3 bytes
              5, 0x42])       # pair 2: count=5, value='B'  → 5 bytes  total=8 ≠ 99

path = "tests/fixtures/f02_rle_mismatch.bun"
with open(path, "wb") as fh:
    fh.write(f02)
print(f"[+] {path}  ({len(f02)} bytes)")
assert len(f02) == 116


# ---------------------------------------------------------------------------
# F-03 — data section at offset 0 overlaps the header, but no check catches it
# ---------------------------------------------------------------------------
# Group 40 checks three pairs of sections for overlap (asset table vs
# string table, asset table vs data section, string table vs data section)
# but never compares any of them against the header which lives at [0, 60).
#
# Setting data_section_offset = 0 puts the data section right on top of
# the header.  All three checks pass fine because they don't involve the
# header, so the parser carries on and reads the BUN magic bytes as the
# asset's data content — "BUN0...." — then exits 0.
#
# Expected: exit 1 (BUN_MALFORMED)   Actual: exit 0 (BUN_OK)
# ---------------------------------------------------------------------------

f03 = bytearray()
f03 += pack_header(
    asset_count=1,
    asset_table_offset=60,
    string_table_offset=108,  string_table_size=4,
    data_section_offset=0,    # <-- overlaps with the header [0, 60)
    data_section_size=8,
)
f03 += pack_asset(
    name_offset=0, name_length=4,
    data_offset=0, data_size=8,   # data lands at file offset 0 = header bytes
    uncompressed_size=0,
    compression=0,
)
f03 += b"test"   # string table  (offset 108, size 4)
# No separate data section needed — it deliberately aliases the header.

path = "tests/fixtures/f03_header_overlap.bun"
with open(path, "wb") as fh:
    fh.write(f03)
print(f"[+] {path}  ({len(f03)} bytes)")
assert len(f03) == 112

print("\nAll fixtures generated successfully.")
