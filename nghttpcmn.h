#pragma once

#include <stdint.h>

typedef struct {
  /* The number of bits in this code */
  uint32_t nbits;
  /* Huffman code aligned to LSB */
  uint32_t code;
} nghttp2_huff_sym;

typedef struct {
  /* huffman decoding state, which is actually the node ID of internal
     huffman tree.  We have 257 leaf nodes, but they are identical to
     root node other than emitting a symbol, so we have 256 internal
     nodes [1..255], inclusive. */
  uint8_t state;
  /* bitwise OR of zero or more of the nghttp2_huff_decode_flag */
  uint8_t flags;
  /* symbol if NGHTTP2_HUFF_SYM flag set */
  uint8_t sym;
} nghttp2_huff_decode;