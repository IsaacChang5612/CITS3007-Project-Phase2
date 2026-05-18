#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bun.h"

static void add_error(BunParseContext *ctx, const char *msg) {
  if (ctx->error_count < MAX_ERRORS) {
    ctx->errors[ctx->error_count++] = msg;
  }
}

// Accumulates new results, and prioritise the "worst" error
// Priority: BUN_ERROR_IO > BUN_MALFORMED > BUN_SUPPORTED > etc
// If no errors then BUN_OK
static bun_result_t worst_error(bun_result_t current, bun_result_t incoming) {
  if (incoming == BUN_ERR_IO || current == BUN_ERR_IO) {
    return BUN_ERR_IO;
  }
  if (incoming == BUN_ERR_CORRUPT || current == BUN_ERR_CORRUPT) {
    return BUN_ERR_IO;
  }
  if (incoming == BUN_ERR_OVERFLOW || current == BUN_ERR_OVERFLOW) {
    return BUN_ERR_OVERFLOW;
  }
  if (incoming == BUN_ERR_SECURITY || current == BUN_ERR_SECURITY) {
    return BUN_ERR_SECURITY;
  }
  if (incoming == BUN_ERR_TRUNCATED || current == BUN_ERR_TRUNCATED) {
    return BUN_ERR_TRUNCATED;
  }
  if (incoming == BUN_MALFORMED || current == BUN_MALFORMED) {
    return BUN_MALFORMED;
  }
  if (incoming == BUN_UNSUPPORTED || current == BUN_UNSUPPORTED) {
    return BUN_UNSUPPORTED;
  }
  return BUN_OK;
}

static u32 read_u32_le(const u8 *buf, size_t offset) {
  return (u32)buf[offset] | (u32)buf[offset + 1] << 8 |
         (u32)buf[offset + 2] << 16 | (u32)buf[offset + 3] << 24;
}

static u64 read_u64_le(const u8 *b, size_t o) {
  return (u64)b[o] | (u64)b[o + 1] << 8 | (u64)b[o + 2] << 16 |
         (u64)b[o + 3] << 24 | (u64)b[o + 4] << 32 | (u64)b[o + 5] << 40 |
         (u64)b[o + 6] << 48 | (u64)b[o + 7] << 56;
}

static int isMagic(const BunHeader *header) {
  return header->magic == BUN_MAGIC;
}

static int validVersion(const BunHeader *header) {
  return header->version_major == BUN_VERSION_MAJOR &&
         header->version_minor == BUN_VERSION_MINOR;
}

static int sectionsAligned(const BunHeader *header) {
  return (header->asset_table_offset % 4 == 0 &&
          header->string_table_offset % 4 == 0 &&
          header->data_section_offset % 4 == 0 &&
          header->string_table_size % 4 == 0 &&
          header->data_section_size % 4 == 0);
}

static int is_printable_ascii(int c) {
  // Printable ASCII characters are from 0x20 (space) to 0x7E (tilde)
  return c >= 0x20 && c <= 0x7E;
}
//
// API implementation
//

bun_result_t bun_open(const char *path, BunParseContext *ctx) {
  // we open the file; seek to the end, to get the size; then jump back to the
  // beginning, ready to start parsing.

  ctx->file = fopen(path, "rb");
  if (!ctx->file) {
    return BUN_ERR_IO;
  }

  ctx->error_count = 0;

  if (fseek(ctx->file, 0, SEEK_END) != 0) {
    fclose(ctx->file);
    return BUN_ERR_IO;
  }
  ctx->file_size = ftell(ctx->file);
  if (ctx->file_size < 0) {
    fclose(ctx->file);
    return BUN_ERR_IO;
  }
  rewind(ctx->file);

  return BUN_OK;
}

bun_result_t bun_parse_header(BunParseContext *ctx, BunHeader *header) {
  bun_result_t result = BUN_OK; // Store status code
  u8 buf[BUN_HEADER_SIZE];

  if (ctx->file_size < (long)BUN_HEADER_SIZE) {
    add_error(ctx, "Truncated file");
    return BUN_ERR_TRUNCATED;
  }

  if (fread(buf, 1, BUN_HEADER_SIZE, ctx->file) != BUN_HEADER_SIZE) {
    add_error(ctx, "Failed to read header");
    result = worst_error(result, BUN_ERR_IO);
  }

  size_t offset = 0;
  header->magic = read_u32_le(buf, offset);
  offset += 4;

  header->version_major = (buf[offset] | (buf[offset + 1] << 8));
  offset += 2;
  header->version_minor = (buf[offset] | (buf[offset + 1] << 8));
  offset += 2;

  header->asset_count = read_u32_le(buf, offset);
  offset += 4;

  header->asset_table_offset = read_u64_le(buf, offset);
  offset += 8;
  header->string_table_offset = read_u64_le(buf, offset);
  offset += 8;
  header->string_table_size = read_u64_le(buf, offset);
  offset += 8;
  header->data_section_offset = read_u64_le(buf, offset);
  offset += 8;
  header->data_section_size = read_u64_le(buf, offset);
  offset += 8;
  header->reserved = read_u64_le(buf, offset);

  if (!isMagic(header)) {
    add_error(ctx, "Invalid magic number");
    result = worst_error(result, BUN_MALFORMED);
  }

  if (!validVersion(header)) {
    add_error(ctx, "Invalid version");
    result = worst_error(result, BUN_UNSUPPORTED);
  }

  return result;
}

/**
 * @brief Validates the integrity of RLE-compressed asset data.
 *
 * @param ctx Pointer to the current parse context for error reporting.
 * @param header Pointer to the parsed BUN header for section offsets.
 * @param r Pointer to the asset record being validated.
 * @return BUN_OK if valid, BUN_MALFORMED on spec violation, or BUN_ERR_IO on
 * read error.
 */
static bun_result_t validate_rle_data(BunParseContext *ctx,
                                      const BunHeader *header,
                                      const BunAssetRecord *r) {
  bun_result_t result = BUN_OK; // Store exit status
  // RLE data must be an even amount of bytes
  if (r->data_size % 2 != 0) {
    add_error(ctx, "RLE data size is not even");
    result = worst_error(result, BUN_MALFORMED);
  }

  // Save current file position to get back to later
  long saved_pos = ftell(ctx->file);
  u64 data_start_abs = header->data_section_offset + r->data_offset;

  if (saved_pos < 0) {
    add_error(ctx, "ftell failed before RLE validation");
    result = worst_error(result, BUN_ERR_IO);
  }
  if (fseek(ctx->file, data_start_abs, SEEK_SET) != 0) {
    add_error(ctx, "Failed to seek to RLE data");
    result = worst_error(result, BUN_ERR_IO);
  }

  // Getting the actual size of the data
  u64 total_expanded = 0;
  for (u64 j = 0; j < r->data_size; j += 2) {
    int count = fgetc(ctx->file);
    int value = fgetc(ctx->file);

    if (count == EOF || value == EOF) {
      add_error(ctx, "Unexpected EOF in RLE data");
      // Cleaning up
      fseek(ctx->file, saved_pos, SEEK_SET);
      result = worst_error(result, BUN_MALFORMED);
      break;
    }

    // A count of zero is a spec violation
    if (count == 0) {
      add_error(ctx, "RLE pair has zero count");
      result = worst_error(result, BUN_MALFORMED);
    }

    total_expanded += (unsigned char)count;
    if (total_expanded > r->uncompressed_size) {
      add_error(ctx, "RLE data is bigger than specified uncompressed_size");
      result = worst_error(result, BUN_MALFORMED);
    }
  }

  // Check if our data size matches the header
  if (total_expanded != r->uncompressed_size) {
    add_error(ctx, "RLE expanded size mismatch");
    fseek(ctx->file, saved_pos, SEEK_SET);
    result = worst_error(result, BUN_ERR_CORRUPT);
  }

  // Restore original file position
  fseek(ctx->file, saved_pos, SEEK_SET);
  return result;
}

bun_result_t bun_parse_assets(BunParseContext *ctx, const BunHeader *header) {
  bun_result_t result = BUN_OK; // Store exit status
  u64 file_size = (u64)ctx->file_size;

  // Check for alignment and offsets
  if (!sectionsAligned(header)) {
    add_error(ctx, "Misaligned section offset or size");
    result = worst_error(result, BUN_MALFORMED);
  }

  if (fseek(ctx->file, header->asset_table_offset, SEEK_SET) != 0) {
    add_error(ctx, "Failed to seek asset table");
    result = worst_error(result, BUN_MALFORMED);
  }

  if (header->asset_table_offset > (u64)ctx->file_size) {
    add_error(ctx, "Invalid asset table offset");
    result = worst_error(result, BUN_MALFORMED);
  }

  if (header->data_section_offset > (u64)ctx->file_size) {
    add_error(ctx, "Invalid data section offset");
    result = worst_error(result, BUN_MALFORMED);
  }

  if (header->string_table_offset > (u64)ctx->file_size) {
    add_error(ctx, "Invalid string table offset");
    result = worst_error(result, BUN_MALFORMED);
  }

  // Check for asset overflow
  // Claude Sonnet 4.6 was used to highlight and create an overflow check
  if (header->asset_count >
      UINT64_MAX - (u64)header->asset_count * BUN_ASSET_RECORD_SIZE) {
    add_error(ctx, "asset_count causes an arithmetic overflow");
    return BUN_ERR_OVERFLOW;
  }

  // Boundary and overlap checks on asset table, string table, and data section
  u64 assetTableStart = header->asset_table_offset;
  u64 assetTableEnd =
      assetTableStart + (u64)header->asset_count * BUN_ASSET_RECORD_SIZE;

  u64 stringTableStart = header->string_table_offset;
  u64 stringTableEnd = stringTableStart + header->string_table_size;

  u64 dataTableStart = header->data_section_offset;
  u64 dataTableEnd = dataTableStart + header->data_section_size;

  if (assetTableEnd > file_size) {
    add_error(ctx, "Asset entry table exceeds EOF");
    result = worst_error(result, BUN_ERR_TRUNCATED);
  }

  if (stringTableEnd > file_size) {
    add_error(ctx, "String table exceeds EOF");
    result = worst_error(result, BUN_ERR_TRUNCATED);
  }

  if (dataTableEnd > file_size) {
    add_error(ctx, "Data section exceeds EOF");
    result = worst_error(result, BUN_ERR_TRUNCATED);
  }

  if (assetTableEnd > stringTableStart && assetTableStart < stringTableEnd) {
    add_error(ctx, "Asset and string table overlap");
    result = worst_error(result, BUN_MALFORMED);
  }

  if (assetTableEnd > dataTableStart && assetTableStart < dataTableEnd) {
    add_error(ctx, "Asset and data section overlap");
    result = worst_error(result, BUN_MALFORMED);
  }

  if (stringTableEnd > dataTableStart && stringTableStart < dataTableEnd) {
    add_error(ctx, "String and data section overlap");
    result = worst_error(result, BUN_MALFORMED);
  }

  if (fseek(ctx->file, (long)assetTableStart, SEEK_SET) != 0) {
    add_error(ctx, "Failed to seek asset table");
    result = worst_error(result, BUN_ERR_IO);
  }

  // Check for excessive asset counts
  if (header->asset_count > 100000) {
    add_error(ctx, "asset_count exceeds safe limit");
    return BUN_ERR_SECURITY;
  }

  for (u32 i = 0; i < header->asset_count; i++) {
    u8 buf[BUN_ASSET_RECORD_SIZE];

    // Go to the current record in the table
    fseek(ctx->file, (long)(assetTableStart + (u64)i * BUN_ASSET_RECORD_SIZE),
          SEEK_SET);

    if (fread(buf, 1, BUN_ASSET_RECORD_SIZE, ctx->file) !=
        BUN_ASSET_RECORD_SIZE) {
      add_error(ctx, "Unexpected EOF in asset record");
      return BUN_MALFORMED;
    }

    // Asset variables
    BunAssetRecord AssetContent;
    size_t o = 0;

    AssetContent.name_offset = read_u32_le(buf, o);
    o += 4;
    AssetContent.name_length = read_u32_le(buf, o);
    o += 4;
    AssetContent.data_offset = read_u64_le(buf, o);
    o += 8;
    AssetContent.data_size = read_u64_le(buf, o);
    o += 8;
    AssetContent.uncompressed_size = read_u64_le(buf, o);
    o += 8;
    AssetContent.compression = read_u32_le(buf, o);
    o += 4;
    AssetContent.type = read_u32_le(buf, o);
    o += 4;
    AssetContent.checksum = read_u32_le(buf, o);
    o += 4;
    AssetContent.flags = read_u32_le(buf, o);

    char name[256] = "<no name>";
    int name_ok = 1;

    // Asset name checks
    if (AssetContent.name_length == 0) {
      add_error(ctx, "Name does not exist");
      result = worst_error(result, BUN_MALFORMED);
      name_ok = 0;
    }

    if ((u64)AssetContent.name_offset + (u64)AssetContent.name_length >
        header->string_table_size) {
      add_error(ctx, "Asset name out of string table bounds");
      result = worst_error(result, BUN_MALFORMED);
      name_ok = 0;
    }
    if (name_ok) {
      u64 name_start_abs =
          header->string_table_offset + AssetContent.name_offset;
      if (fseek(ctx->file, name_start_abs, SEEK_SET) != 0) {
        add_error(ctx, "Failed to seek to asset name");
        result = worst_error(result, BUN_MALFORMED);
        name_ok = 0;
      }

      if (name_ok) {
        u32 read_len =
            AssetContent.name_length < 255 ? AssetContent.name_length : 255;
        if (fread(name, 1, read_len, ctx->file) != read_len) {
          add_error(ctx, "Failed to read asset name");
          result = worst_error(result, BUN_MALFORMED);
          name_ok = 0;
        } else {
          name[read_len] = '\0';
        }
      }

      if (name_ok) {
        fseek(ctx->file, name_start_abs, SEEK_SET);
        for (u32 j = 0; j < AssetContent.name_length; j++) {
          int c = fgetc(ctx->file);
          if (c == EOF) {
            add_error(ctx, "Unexpected EOF in asset name");
            result = worst_error(result, BUN_MALFORMED);
            break;
          }
          if (!is_printable_ascii(c)) {
            add_error(ctx, "Non-printable asset name");
            result = worst_error(result, BUN_MALFORMED);
            break;
          }
        }
      }
    }

    if (AssetContent.data_offset + AssetContent.data_size >
        header->data_section_size) {
      add_error(ctx, "Asset data out of bounds");
      result = worst_error(result, BUN_MALFORMED);
    }

    // Compression checks
    if (AssetContent.compression == 1) {
      // We use &AssetContent here because validate_rle_data needs a pointer
      bun_result_t rle_res = validate_rle_data(ctx, header, &AssetContent);
      result = worst_error(result, rle_res);
    } else if (AssetContent.compression == 0 &&
               AssetContent.uncompressed_size != 0) {
      add_error(
          ctx,
          "Can't have non-zero uncompressed size for an uncompressed asset");
      result = worst_error(result, BUN_MALFORMED);
    } else if (AssetContent.compression == 2) {
      add_error(ctx, "zlib compression is not supported");
      result = worst_error(result, BUN_UNSUPPORTED);
    } else if (AssetContent.compression > 2) {
      add_error(ctx, "Unknown compression type");
      result = worst_error(result, BUN_MALFORMED);
    }

    if (AssetContent.checksum != 0) {
      add_error(ctx, "CRC-32 checksum validation is not supported");
      result = worst_error(result, BUN_UNSUPPORTED);
    }

    if (AssetContent.flags & ~(BUN_FLAG_ENCRYPTED | BUN_FLAG_EXECUTABLE)) {
      add_error(ctx, "Asset flags field contains unknown bits");
      result = worst_error(result, BUN_UNSUPPORTED);
    }

    // Asset output
    printf("------------ Asset %u ------------\n", i);
    printf("Name:                %s%s\n", name,
           AssetContent.name_length > 255 ? "..." : "");
    printf("Type:                %u\n", AssetContent.type);
    printf("Size:                %llu\n",
           (unsigned long long)AssetContent.data_size);
    printf("Uncompressed Size:   %llu\n",
           (unsigned long long)AssetContent.uncompressed_size);
    printf("Compression:         %u\n", AssetContent.compression);
    printf("Checksum:            0x%08X\n", AssetContent.checksum);
    printf("Flags:               0x%08X\n", AssetContent.flags);

    printf("Preview (Hex):       ");
    if (fseek(ctx->file, header->data_section_offset + AssetContent.data_offset,
              SEEK_SET) == 0) {
      u8 preview_buf[16];
      size_t to_read =
          AssetContent.data_size < 16 ? AssetContent.data_size : 16;
      size_t read_bytes = fread(preview_buf, 1, to_read, ctx->file);
      for (size_t k = 0; k < read_bytes; k++) {
        printf("%02X ", preview_buf[k]);
      }
      printf("\nPreview (ASCII):     ");
      for (size_t k = 0; k < read_bytes; k++) {
        if (is_printable_ascii(preview_buf[k])) {
          printf("%c", preview_buf[k]);
        } else {
          printf(".");
        }
      }
      if (AssetContent.data_size > 16)
        printf("...");
    }
    printf("\n\n");
  }

  return result;
}

bun_result_t bun_close(BunParseContext *ctx) {
  int res = fclose(ctx->file);
  ctx->file = NULL;
  return res ? BUN_ERR_IO : BUN_OK;
}
