#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "bun.h"

static int map_exit_code(bun_result_t r) {
  switch (r) {
  case BUN_OK:
    return 0;
  case BUN_MALFORMED:
    return 1;
  case BUN_UNSUPPORTED:
    return 2;
  case BUN_ERR_IO:
    return 3;
  case BUN_ERR_TRUNCATED:
    return 4;
  case BUN_ERR_OVERFLOW:
    return 5;
  case BUN_ERR_SECURITY:
    return 6;
  case BUN_ERR_CORRUPT:
    return 7;
  default:
    // Default returns 3 as any unknown error code is an unexpected internal
    // problem
    return 3;
  }
}

static void print_result_code(bun_result_t r) {
  // Check status code and print standard error for given code
  // Exit with no errors if status code is BUN_OK
  switch (r) {
  case BUN_MALFORMED:
    fprintf(stderr, "Exit with status code 1 (BUN_MALFORMED)\n");
    break;
  case BUN_UNSUPPORTED:
    fprintf(stderr, "Exit with status code 2 (BUN_SUPPORTED)\n");
    break;
  case BUN_ERR_IO:
    fprintf(stderr, "Exit with status code 3 (BUN_ERR_IO)\n");
    break;
  case BUN_ERR_TRUNCATED:
    fprintf(stderr, "Exit with status code 4 (BUN_ERR_TRUNCATED)\n");
    break;
  case BUN_ERR_OVERFLOW:
    fprintf(stderr, "Exit with status code 5 (BUN_ERR_OVERFLOW)\n");
    break;
  case BUN_ERR_SECURITY:
    fprintf(stderr, "Exit with status code 6 (BUN_ERR_SECURITY)\n");
    break;
  case BUN_ERR_CORRUPT:
    fprintf(stderr, "Exit with status code 7 (BUN_ERR_CORRUPT)\n");
    break;
  default:
  case BUN_OK:
    break;
  }
}

static void print_errors(BunParseContext *ctx) {
  for (int i = 0; i < ctx->error_count; i++) {
    fprintf(stderr, "%s\n", ctx->errors[i]);
  }
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <file.bun>\n", argv[0]);
    return BUN_ERR_IO;
  }
  const char *path = argv[1];

  BunParseContext ctx = {0};
  BunHeader header = {0};

  bun_result_t result = bun_open(path, &ctx);
  if (result != BUN_OK) {
    fprintf(stderr, "Error: could not open '%s'\n", path);
    return map_exit_code(result);
  }

  result = bun_parse_header(&ctx, &header);
  if (result != BUN_OK) {
    print_errors(&ctx);
    print_result_code(result);
    bun_close(&ctx);
    return map_exit_code(result);
  }

  // Print header summary
  printf("------------ BUN Header ------------\n");
  printf("Magic:                0x%08X (BUN0)\n", header.magic);
  printf("Version:              %u.%u\n", header.version_major,
         header.version_minor);
  printf("Asset Count:          %u\n", header.asset_count);
  printf("Asset Table Offset:   %" PRIu64 "\n", header.asset_table_offset);
  printf("String Table Offset:  %" PRIu64 "\n", header.string_table_offset);
  printf("String Table Size:    %" PRIu64 "\n", header.string_table_size);
  printf("Data Section Offset:  %" PRIu64 "\n", header.data_section_offset);
  printf("Data Section Size:    %" PRIu64 "\n\n", header.data_section_size);

  // Parse assets (printing happens inside the loop in bun_parse.c)
  result = bun_parse_assets(&ctx, &header);
  if (result != BUN_OK) {
    print_errors(&ctx);
    print_result_code(result);
  }

  bun_close(&ctx);
  return map_exit_code(result);
}
