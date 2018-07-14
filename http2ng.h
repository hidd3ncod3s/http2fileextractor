#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include "nghttpcmn.h"
#include <string.h>
#include <assert.h>

#ifdef DEBUG
#  define DEBUGF(...) printf(__VA_ARGS__)
#else
#  define DEBUGF(...) 
#endif

#define NGHTTP2_DEFAULT_HEADER_TABLE_SIZE (1 << 12)
#define NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE NGHTTP2_DEFAULT_HEADER_TABLE_SIZE
#define NGHTTP2_HD_ENTRY_OVERHEAD 32

/* The maximum length of one name/value pair.  This is the sum of the
   length of name and value.  This is not specified by the spec. We
   just chose the arbitrary size */
#define NGHTTP2_HD_MAX_NV 65536

/* Default size of maximum table buffer size for encoder. Even if
   remote decoder notifies larger buffer size for its decoding,
   encoder only uses the memory up to this value. */
#define NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE (1 << 12)

/* Exported for unit test */
#define NGHTTP2_STATIC_TABLE_LENGTH 61


#define NGHTTP2_CLIENT_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define NGHTTP2_CLIENT_MAGIC_LEN 24

typedef enum {
  /**
   * The DATA frame.
   */
  NGHTTP2_DATA = 0,
  /**
   * The HEADERS frame.
   */
  NGHTTP2_HEADERS = 0x01,
  /**
   * The PRIORITY frame.
   */
  NGHTTP2_PRIORITY = 0x02,
  /**
   * The RST_STREAM frame.
   */
  NGHTTP2_RST_STREAM = 0x03,
  /**
   * The SETTINGS frame.
   */
  NGHTTP2_SETTINGS = 0x04,
  /**
   * The PUSH_PROMISE frame.
   */
  NGHTTP2_PUSH_PROMISE = 0x05,
  /**
   * The PING frame.
   */
  NGHTTP2_PING = 0x06,
  /**
   * The GOAWAY frame.
   */
  NGHTTP2_GOAWAY = 0x07,
  /**
   * The WINDOW_UPDATE frame.
   */
  NGHTTP2_WINDOW_UPDATE = 0x08,
  /**
   * The CONTINUATION frame.  This frame type won't be passed to any
   * callbacks because the library processes this frame type and its
   * preceding HEADERS/PUSH_PROMISE as a single frame.
   */
  NGHTTP2_CONTINUATION = 0x09,
  /**
   * The ALTSVC frame, which is defined in `RFC 7383
   * <https://tools.ietf.org/html/rfc7838#section-4>`_.
   */
  NGHTTP2_ALTSVC = 0x0a,
  /**
   * The ORIGIN frame, which is defined by `RFC 8336
   * <https://tools.ietf.org/html/rfc8336>`_.
   */
  NGHTTP2_ORIGIN = 0x0c,
  NGHTTP2_UNKNOWN = 0xff,
} nghttp2_frame_type;

/**
 * @enum
 *
 * The flags for HTTP/2 frames.  This enum defines all flags for all
 * frames.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_FLAG_NONE = 0,
  /**
   * The END_STREAM flag.
   */
  NGHTTP2_FLAG_END_STREAM = 0x01,
  /**
   * The END_HEADERS flag.
   */
  NGHTTP2_FLAG_END_HEADERS = 0x04,
  /**
   * The ACK flag.
   */
  NGHTTP2_FLAG_ACK = 0x01,
  /**
   * The PADDED flag.
   */
  NGHTTP2_FLAG_PADDED = 0x08,
  /**
   * The PRIORITY flag.
   */
  NGHTTP2_FLAG_PRIORITY = 0x20
} nghttp2_flag;

/**
 * @enum
 * The SETTINGS ID.
 */
typedef enum {
  /**
   * SETTINGS_HEADER_TABLE_SIZE
   */
  NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x01,
  /**
   * SETTINGS_ENABLE_PUSH
   */
  NGHTTP2_SETTINGS_ENABLE_PUSH = 0x02,
  /**
   * SETTINGS_MAX_CONCURRENT_STREAMS
   */
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
  /**
   * SETTINGS_INITIAL_WINDOW_SIZE
   */
  NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
  /**
   * SETTINGS_MAX_FRAME_SIZE
   */
  NGHTTP2_SETTINGS_MAX_FRAME_SIZE = 0x05,
  /**
   * SETTINGS_MAX_HEADER_LIST_SIZE
   */
  NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x06
} nghttp2_settings_id;

/**
 * @enum
 * The status codes for the RST_STREAM and GOAWAY frames.
 */
typedef enum {
  /**
   * No errors.
   */
  NGHTTP2_NO_ERROR = 0x00,
  /**
   * PROTOCOL_ERROR
   */
  NGHTTP2_PROTOCOL_ERROR = 0x01,
  /**
   * INTERNAL_ERROR
   */
  NGHTTP2_INTERNAL_ERROR = 0x02,
  /**
   * FLOW_CONTROL_ERROR
   */
  NGHTTP2_FLOW_CONTROL_ERROR = 0x03,
  /**
   * SETTINGS_TIMEOUT
   */
  NGHTTP2_SETTINGS_TIMEOUT = 0x04,
  /**
   * STREAM_CLOSED
   */
  NGHTTP2_STREAM_CLOSED = 0x05,
  /**
   * FRAME_SIZE_ERROR
   */
  NGHTTP2_FRAME_SIZE_ERROR = 0x06,
  /**
   * REFUSED_STREAM
   */
  NGHTTP2_REFUSED_STREAM = 0x07,
  /**
   * CANCEL
   */
  NGHTTP2_CANCEL = 0x08,
  /**
   * COMPRESSION_ERROR
   */
  NGHTTP2_COMPRESSION_ERROR = 0x09,
  /**
   * CONNECT_ERROR
   */
  NGHTTP2_CONNECT_ERROR = 0x0a,
  /**
   * ENHANCE_YOUR_CALM
   */
  NGHTTP2_ENHANCE_YOUR_CALM = 0x0b,
  /**
   * INADEQUATE_SECURITY
   */
  NGHTTP2_INADEQUATE_SECURITY = 0x0c,
  /**
   * HTTP_1_1_REQUIRED
   */
  NGHTTP2_HTTP_1_1_REQUIRED = 0x0d
} nghttp2_error_code;


typedef enum {
  NGHTTP2_HD_OPCODE_NONE,
  NGHTTP2_HD_OPCODE_INDEXED,
  NGHTTP2_HD_OPCODE_NEWNAME,
  NGHTTP2_HD_OPCODE_INDNAME
} nghttp2_hd_opcode;

typedef enum {
  NGHTTP2_HD_STATE_EXPECT_TABLE_SIZE,
  NGHTTP2_HD_STATE_INFLATE_START,
  NGHTTP2_HD_STATE_OPCODE,
  NGHTTP2_HD_STATE_READ_TABLE_SIZE,
  NGHTTP2_HD_STATE_READ_INDEX,
  NGHTTP2_HD_STATE_NEWNAME_CHECK_NAMELEN,
  NGHTTP2_HD_STATE_NEWNAME_READ_NAMELEN,
  NGHTTP2_HD_STATE_NEWNAME_READ_NAMEHUFF,
  NGHTTP2_HD_STATE_NEWNAME_READ_NAME,
  NGHTTP2_HD_STATE_CHECK_VALUELEN,
  NGHTTP2_HD_STATE_READ_VALUELEN,
  NGHTTP2_HD_STATE_READ_VALUEHUFF,
  NGHTTP2_HD_STATE_READ_VALUE
} nghttp2_hd_inflate_state;

typedef enum {
  NGHTTP2_HD_WITH_INDEXING,
  NGHTTP2_HD_WITHOUT_INDEXING,
  NGHTTP2_HD_NEVER_INDEXING
} nghttp2_hd_indexing_mode;

/**
 * @enum
 *
 * The flags for header inflation.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_HD_INFLATE_NONE = 0,
  /**
   * Indicates all headers were inflated.
   */
  NGHTTP2_HD_INFLATE_FINAL = 0x01,
  /**
   * Indicates a header was emitted.
   */
  NGHTTP2_HD_INFLATE_EMIT = 0x02
} nghttp2_hd_inflate_flag;


/* Make scalar initialization form of nghttp2_hd_entry */
#define MAKE_STATIC_ENT(N, V, T, H)                                            \
  {                                                                            \
    {NULL, NULL, (uint8_t *)(N), sizeof((N)) - 1, -1},                         \
        {NULL, NULL, (uint8_t *)(V), sizeof((V)) - 1, -1},                     \
        {(uint8_t *)(N), (uint8_t *)(V), sizeof((N)) - 1, sizeof((V)) - 1, 0}, \
        T, H                                                                   \
  }

/**
 * @functypedef
 *
 * Custom memory allocator to replace malloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void *(*nghttp2_malloc)(size_t size, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace free().  The |mem_user_data| is
 * the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void (*nghttp2_free)(void *ptr, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace calloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void *(*nghttp2_calloc)(size_t nmemb, size_t size, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace realloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void *(*nghttp2_realloc)(void *ptr, size_t size, void *mem_user_data);

/**
 * @struct
 *
 * Custom memory allocator functions and user defined pointer.  The
 * |mem_user_data| member is passed to each allocator function.  This
 * can be used, for example, to achieve per-session memory pool.
 *
 * In the following example code, ``my_malloc``, ``my_free``,
 * ``my_calloc`` and ``my_realloc`` are the replacement of the
 * standard allocators ``malloc``, ``free``, ``calloc`` and
 * ``realloc`` respectively::
 *
 *     void *my_malloc_cb(size_t size, void *mem_user_data) {
 *       return my_malloc(size);
 *     }
 *
 *     void my_free_cb(void *ptr, void *mem_user_data) { my_free(ptr); }
 *
 *     void *my_calloc_cb(size_t nmemb, size_t size, void *mem_user_data) {
 *       return my_calloc(nmemb, size);
 *     }
 *
 *     void *my_realloc_cb(void *ptr, size_t size, void *mem_user_data) {
 *       return my_realloc(ptr, size);
 *     }
 *
 *     void session_new() {
 *       nghttp2_session *session;
 *       nghttp2_session_callbacks *callbacks;
 *       nghttp2_mem mem = {NULL, my_malloc_cb, my_free_cb, my_calloc_cb,
 *                          my_realloc_cb};
 *
 *       ...
 *
 *       nghttp2_session_client_new3(&session, callbacks, NULL, NULL, &mem);
 *
 *       ...
 *     }
 */
typedef struct {
  /**
   * An arbitrary user supplied data.  This is passed to each
   * allocator function.
   */
  void *mem_user_data;
  /**
   * Custom allocator function to replace malloc().
   */
  nghttp2_malloc malloc;
  /**
   * Custom allocator function to replace free().
   */
  nghttp2_free free;
  /**
   * Custom allocator function to replace calloc().
   */
  nghttp2_calloc calloc;
  /**
   * Custom allocator function to replace realloc().
   */
  nghttp2_realloc realloc;
} nghttp2_mem;

typedef struct {
  /* Current huffman decoding state. We stripped leaf nodes, so the
     value range is [0..255], inclusive. */
  uint8_t state;
  /* nonzero if we can say that the decoding process succeeds at this
     state */
  uint8_t accept;
} nghttp2_hd_huff_decode_context;

/**
 * @struct
 *
 * The object representing reference counted buffer.  The details of
 * this structure are intentionally hidden from the public API.
 */
typedef struct nghttp2_rcbuf nghttp2_rcbuf;

/**
 * @struct
 *
 * The name/value pair, which mainly used to represent header fields.
 */
typedef struct {
  /**
   * The |name| byte string.  If this struct is presented from library
   * (e.g., :type:`nghttp2_on_frame_recv_callback`), |name| is
   * guaranteed to be NULL-terminated.  For some callbacks
   * (:type:`nghttp2_before_frame_send_callback`,
   * :type:`nghttp2_on_frame_send_callback`, and
   * :type:`nghttp2_on_frame_not_send_callback`), it may not be
   * NULL-terminated if header field is passed from application with
   * the flag :enum:`NGHTTP2_NV_FLAG_NO_COPY_NAME`).  When application
   * is constructing this struct, |name| is not required to be
   * NULL-terminated.
   */
  uint8_t *name;
  /**
   * The |value| byte string.  If this struct is presented from
   * library (e.g., :type:`nghttp2_on_frame_recv_callback`), |value|
   * is guaranteed to be NULL-terminated.  For some callbacks
   * (:type:`nghttp2_before_frame_send_callback`,
   * :type:`nghttp2_on_frame_send_callback`, and
   * :type:`nghttp2_on_frame_not_send_callback`), it may not be
   * NULL-terminated if header field is passed from application with
   * the flag :enum:`NGHTTP2_NV_FLAG_NO_COPY_VALUE`).  When
   * application is constructing this struct, |value| is not required
   * to be NULL-terminated.
   */
  uint8_t *value;
  /**
   * The length of the |name|, excluding terminating NULL.
   */
  size_t namelen;
  /**
   * The length of the |value|, excluding terminating NULL.
   */
  size_t valuelen;
  /**
   * Bitwise OR of one or more of :type:`nghttp2_nv_flag`.
   */
  uint8_t flags;
} nghttp2_nv;

typedef struct {
  /* The buffer containing header field name.  NULL-termination is
     guaranteed. */
  nghttp2_rcbuf *name;
  /* The buffer containing header field value.  NULL-termination is
     guaranteed. */
  nghttp2_rcbuf *value;
  /* nghttp2_token value for name.  It could be -1 if we have no token
     for that header field name. */
  int32_t token;
  /* Bitwise OR of one or more of nghttp2_nv_flag. */
  uint8_t flags;
} nghttp2_hd_nv;

struct nghttp2_hd_entry;
typedef struct nghttp2_hd_entry nghttp2_hd_entry;

struct nghttp2_hd_entry {
  /* The header field name/value pair */
  nghttp2_hd_nv nv;
  /* This is solely for nghttp2_hd_{deflate,inflate}_get_table_entry
     APIs to keep backward compatibility. */
  nghttp2_nv cnv;
  /* The next entry which shares same bucket in hash table. */
  nghttp2_hd_entry *next;
  /* The sequence number.  We will increment it by one whenever we
     store nghttp2_hd_entry to dynamic header table. */
  uint32_t seq;
  /* The hash value for header name (nv.name). */
  uint32_t hash;
};

  
struct nghttp2_rcbuf {
  /* custom memory allocator belongs to the mem parameter when
     creating this object. */
  void *mem_user_data;
  nghttp2_free free;
  /* The pointer to the underlying buffer */
  uint8_t *base;
  /* Size of buffer pointed by |base|. */
  size_t len;
  /* Reference count */
  int32_t ref;
};

typedef struct {
  nghttp2_hd_entry **buffer;
  size_t mask;
  size_t first;
  size_t len;
} nghttp2_hd_ringbuf;

/* The entry used for static header table. */
typedef struct {
  nghttp2_rcbuf name;
  nghttp2_rcbuf value;
  nghttp2_nv cnv;
  int32_t token;
  uint32_t hash;
} nghttp2_hd_static_entry;

typedef struct {
  /* dynamic header table */
  nghttp2_hd_ringbuf hd_table;
  /* Memory allocator */
  nghttp2_mem *mem;
  /* Abstract buffer size of hd_table as described in the spec. This
     is the sum of length of name/value in hd_table +
     NGHTTP2_HD_ENTRY_OVERHEAD bytes overhead per each entry. */
  size_t hd_table_bufsize;
  /* The effective header table size. */
  size_t hd_table_bufsize_max;
  /* Next sequence number for nghttp2_hd_entry */
  uint32_t next_seq;
  /* If inflate/deflate error occurred, this value is set to 1 and
     further invocation of inflate/deflate will fail with
     NGHTTP2_ERR_HEADER_COMP. */
  uint8_t bad;
} nghttp2_hd_context;

typedef struct {
  /* This points to the beginning of the buffer. The effective range
     of buffer is [begin, end). */
  uint8_t *begin;
  /* This points to the memory one byte beyond the end of the
     buffer. */
  uint8_t *end;
  /* The position indicator for effective start of the buffer. pos <=
     last must be hold. */
  uint8_t *pos;
  /* The position indicator for effective one beyond of the end of the
     buffer. last <= end must be hold. */
  uint8_t *last;
  /* Mark arbitrary position in buffer [begin, end) */
  uint8_t *mark;
} nghttp2_buf;

struct nghttp2_hd_inflater {
  nghttp2_hd_context ctx;
  /* Stores current state of huffman decoding */
  nghttp2_hd_huff_decode_context huff_decode_ctx;
  /* header buffer */
  nghttp2_buf namebuf, valuebuf;
  nghttp2_rcbuf *namercbuf, *valuercbuf;
  /* Pointer to the name/value pair which are used in the current
     header emission. */
  nghttp2_rcbuf *nv_name_keep, *nv_value_keep;
  /* The number of bytes to read */
  size_t left;
  /* The index in indexed repr or indexed name */
  size_t index;
  /* The maximum header table size the inflater supports. This is the
     same value transmitted in SETTINGS_HEADER_TABLE_SIZE */
  size_t settings_hd_table_bufsize_max;
  /* Minimum header table size set by nghttp2_hd_inflate_change_table_size */
  size_t min_hd_table_bufsize_max;
  /* The number of next shift to decode integer */
  size_t shift;
  nghttp2_hd_opcode opcode;
  nghttp2_hd_inflate_state state;
  /* nonzero if string is huffman encoded */
  uint8_t huffman_encoded;
  /* nonzero if deflater requires that current entry is indexed */
  uint8_t index_required;
  /* nonzero if deflater requires that current entry must not be
     indexed */
  uint8_t no_index;
};

/**
 * @enum
 *
 * Error codes used in this library.  The code range is [-999, -500],
 * inclusive. The following values are defined:
 */
typedef enum {
  /**
   * Invalid argument passed.
   */
  NGHTTP2_ERR_INVALID_ARGUMENT = -501,
  /**
   * Out of buffer space.
   */
  NGHTTP2_ERR_BUFFER_ERROR = -502,
  /**
   * The specified protocol version is not supported.
   */
  NGHTTP2_ERR_UNSUPPORTED_VERSION = -503,
  /**
   * Used as a return value from :type:`nghttp2_send_callback`,
   * :type:`nghttp2_recv_callback` and
   * :type:`nghttp2_send_data_callback` to indicate that the operation
   * would block.
   */
  NGHTTP2_ERR_WOULDBLOCK = -504,
  /**
   * General protocol error
   */
  NGHTTP2_ERR_PROTO = -505,
  /**
   * The frame is invalid.
   */
  NGHTTP2_ERR_INVALID_FRAME = -506,
  /**
   * The peer performed a shutdown on the connection.
   */
  NGHTTP2_ERR_EOF = -507,
  /**
   * Used as a return value from
   * :func:`nghttp2_data_source_read_callback` to indicate that data
   * transfer is postponed.  See
   * :func:`nghttp2_data_source_read_callback` for details.
   */
  NGHTTP2_ERR_DEFERRED = -508,
  /**
   * Stream ID has reached the maximum value.  Therefore no stream ID
   * is available.
   */
  NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE = -509,
  /**
   * The stream is already closed; or the stream ID is invalid.
   */
  NGHTTP2_ERR_STREAM_CLOSED = -510,
  /**
   * RST_STREAM has been added to the outbound queue.  The stream is
   * in closing state.
   */
  NGHTTP2_ERR_STREAM_CLOSING = -511,
  /**
   * The transmission is not allowed for this stream (e.g., a frame
   * with END_STREAM flag set has already sent).
   */
  NGHTTP2_ERR_STREAM_SHUT_WR = -512,
  /**
   * The stream ID is invalid.
   */
  NGHTTP2_ERR_INVALID_STREAM_ID = -513,
  /**
   * The state of the stream is not valid (e.g., DATA cannot be sent
   * to the stream if response HEADERS has not been sent).
   */
  NGHTTP2_ERR_INVALID_STREAM_STATE = -514,
  /**
   * Another DATA frame has already been deferred.
   */
  NGHTTP2_ERR_DEFERRED_DATA_EXIST = -515,
  /**
   * Starting new stream is not allowed (e.g., GOAWAY has been sent
   * and/or received).
   */
  NGHTTP2_ERR_START_STREAM_NOT_ALLOWED = -516,
  /**
   * GOAWAY has already been sent.
   */
  NGHTTP2_ERR_GOAWAY_ALREADY_SENT = -517,
  /**
   * The received frame contains the invalid header block (e.g., There
   * are duplicate header names; or the header names are not encoded
   * in US-ASCII character set and not lower cased; or the header name
   * is zero-length string; or the header value contains multiple
   * in-sequence NUL bytes).
   */
  NGHTTP2_ERR_INVALID_HEADER_BLOCK = -518,
  /**
   * Indicates that the context is not suitable to perform the
   * requested operation.
   */
  NGHTTP2_ERR_INVALID_STATE = -519,
  /**
   * The user callback function failed due to the temporal error.
   */
  NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE = -521,
  /**
   * The length of the frame is invalid, either too large or too small.
   */
  NGHTTP2_ERR_FRAME_SIZE_ERROR = -522,
  /**
   * Header block inflate/deflate error.
   */
  NGHTTP2_ERR_HEADER_COMP = -523,
  /**
   * Flow control error
   */
  NGHTTP2_ERR_FLOW_CONTROL = -524,
  /**
   * Insufficient buffer size given to function.
   */
  NGHTTP2_ERR_INSUFF_BUFSIZE = -525,
  /**
   * Callback was paused by the application
   */
  NGHTTP2_ERR_PAUSE = -526,
  /**
   * There are too many in-flight SETTING frame and no more
   * transmission of SETTINGS is allowed.
   */
  NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS = -527,
  /**
   * The server push is disabled.
   */
  NGHTTP2_ERR_PUSH_DISABLED = -528,
  /**
   * DATA or HEADERS frame for a given stream has been already
   * submitted and has not been fully processed yet.  Application
   * should wait for the transmission of the previously submitted
   * frame before submitting another.
   */
  NGHTTP2_ERR_DATA_EXIST = -529,
  /**
   * The current session is closing due to a connection error or
   * `nghttp2_session_terminate_session()` is called.
   */
  NGHTTP2_ERR_SESSION_CLOSING = -530,
  /**
   * Invalid HTTP header field was received and stream is going to be
   * closed.
   */
  NGHTTP2_ERR_HTTP_HEADER = -531,
  /**
   * Violation in HTTP messaging rule.
   */
  NGHTTP2_ERR_HTTP_MESSAGING = -532,
  /**
   * Stream was refused.
   */
  NGHTTP2_ERR_REFUSED_STREAM = -533,
  /**
   * Unexpected internal error, but recovered.
   */
  NGHTTP2_ERR_INTERNAL = -534,
  /**
   * Indicates that a processing was canceled.
   */
  NGHTTP2_ERR_CANCEL = -535,
  /**
   * When a local endpoint expects to receive SETTINGS frame, it
   * receives an other type of frame.
   */
  NGHTTP2_ERR_SETTINGS_EXPECTED = -536,
  /**
   * The errors < :enum:`NGHTTP2_ERR_FATAL` mean that the library is
   * under unexpected condition and processing was terminated (e.g.,
   * out of memory).  If application receives this error code, it must
   * stop using that :type:`nghttp2_session` object and only allowed
   * operation for that object is deallocate it using
   * `nghttp2_session_del()`.
   */
  NGHTTP2_ERR_FATAL = -900,
  /**
   * Out of memory.  This is a fatal error.
   */
  NGHTTP2_ERR_NOMEM = -901,
  /**
   * The user callback function failed.  This is a fatal error.
   */
  NGHTTP2_ERR_CALLBACK_FAILURE = -902,
  /**
   * Invalid client magic (see :macro:`NGHTTP2_CLIENT_MAGIC`) was
   * received and further processing is not possible.
   */
  NGHTTP2_ERR_BAD_CLIENT_MAGIC = -903,
  /**
   * Possible flooding by peer was detected in this HTTP/2 session.
   * Flooding is measured by how many PING and SETTINGS frames with
   * ACK flag set are queued for transmission.  These frames are
   * response for the peer initiated frames, and peer can cause memory
   * exhaustion on server side to send these frames forever and does
   * not read network.
   */
  NGHTTP2_ERR_FLOODED = -904
} nghttp2_error;

/* Exported for unit test */
#define NGHTTP2_STATIC_TABLE_LENGTH 61

/**
 * @enum
 *
 * The flags for header field name/value pair.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_NV_FLAG_NONE = 0,
  /**
   * Indicates that this name/value pair must not be indexed ("Literal
   * Header Field never Indexed" representation must be used in HPACK
   * encoding).  Other implementation calls this bit as "sensitive".
   */
  NGHTTP2_NV_FLAG_NO_INDEX = 0x01,
  /**
   * This flag is set solely by application.  If this flag is set, the
   * library does not make a copy of header field name.  This could
   * improve performance.
   */
  NGHTTP2_NV_FLAG_NO_COPY_NAME = 0x02,
  /**
   * This flag is set solely by application.  If this flag is set, the
   * library does not make a copy of header field value.  This could
   * improve performance.
   */
  NGHTTP2_NV_FLAG_NO_COPY_VALUE = 0x04
} nghttp2_nv_flag;

/* The maximum length of one name/value pair.  This is the sum of the
   length of name and value.  This is not specified by the spec. We
   just chose the arbitrary size */
#define NGHTTP2_HD_MAX_NV 65536

#define HD_MAP_SIZE 128

typedef struct {
  nghttp2_hd_entry *table[HD_MAP_SIZE];
} nghttp2_hd_map;

/* Generated by genlibtokenlookup.py */
typedef enum {
  NGHTTP2_TOKEN__AUTHORITY = 0,
  NGHTTP2_TOKEN__METHOD = 1,
  NGHTTP2_TOKEN__PATH = 3,
  NGHTTP2_TOKEN__SCHEME = 5,
  NGHTTP2_TOKEN__STATUS = 7,
  NGHTTP2_TOKEN_ACCEPT_CHARSET = 14,
  NGHTTP2_TOKEN_ACCEPT_ENCODING = 15,
  NGHTTP2_TOKEN_ACCEPT_LANGUAGE = 16,
  NGHTTP2_TOKEN_ACCEPT_RANGES = 17,
  NGHTTP2_TOKEN_ACCEPT = 18,
  NGHTTP2_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN = 19,
  NGHTTP2_TOKEN_AGE = 20,
  NGHTTP2_TOKEN_ALLOW = 21,
  NGHTTP2_TOKEN_AUTHORIZATION = 22,
  NGHTTP2_TOKEN_CACHE_CONTROL = 23,
  NGHTTP2_TOKEN_CONTENT_DISPOSITION = 24,
  NGHTTP2_TOKEN_CONTENT_ENCODING = 25,
  NGHTTP2_TOKEN_CONTENT_LANGUAGE = 26,
  NGHTTP2_TOKEN_CONTENT_LENGTH = 27,
  NGHTTP2_TOKEN_CONTENT_LOCATION = 28,
  NGHTTP2_TOKEN_CONTENT_RANGE = 29,
  NGHTTP2_TOKEN_CONTENT_TYPE = 30,
  NGHTTP2_TOKEN_COOKIE = 31,
  NGHTTP2_TOKEN_DATE = 32,
  NGHTTP2_TOKEN_ETAG = 33,
  NGHTTP2_TOKEN_EXPECT = 34,
  NGHTTP2_TOKEN_EXPIRES = 35,
  NGHTTP2_TOKEN_FROM = 36,
  NGHTTP2_TOKEN_HOST = 37,
  NGHTTP2_TOKEN_IF_MATCH = 38,
  NGHTTP2_TOKEN_IF_MODIFIED_SINCE = 39,
  NGHTTP2_TOKEN_IF_NONE_MATCH = 40,
  NGHTTP2_TOKEN_IF_RANGE = 41,
  NGHTTP2_TOKEN_IF_UNMODIFIED_SINCE = 42,
  NGHTTP2_TOKEN_LAST_MODIFIED = 43,
  NGHTTP2_TOKEN_LINK = 44,
  NGHTTP2_TOKEN_LOCATION = 45,
  NGHTTP2_TOKEN_MAX_FORWARDS = 46,
  NGHTTP2_TOKEN_PROXY_AUTHENTICATE = 47,
  NGHTTP2_TOKEN_PROXY_AUTHORIZATION = 48,
  NGHTTP2_TOKEN_RANGE = 49,
  NGHTTP2_TOKEN_REFERER = 50,
  NGHTTP2_TOKEN_REFRESH = 51,
  NGHTTP2_TOKEN_RETRY_AFTER = 52,
  NGHTTP2_TOKEN_SERVER = 53,
  NGHTTP2_TOKEN_SET_COOKIE = 54,
  NGHTTP2_TOKEN_STRICT_TRANSPORT_SECURITY = 55,
  NGHTTP2_TOKEN_TRANSFER_ENCODING = 56,
  NGHTTP2_TOKEN_USER_AGENT = 57,
  NGHTTP2_TOKEN_VARY = 58,
  NGHTTP2_TOKEN_VIA = 59,
  NGHTTP2_TOKEN_WWW_AUTHENTICATE = 60,
  NGHTTP2_TOKEN_TE,
  NGHTTP2_TOKEN_CONNECTION,
  NGHTTP2_TOKEN_KEEP_ALIVE,
  NGHTTP2_TOKEN_PROXY_CONNECTION,
  NGHTTP2_TOKEN_UPGRADE,
} nghttp2_token;

/**
 * @struct
 *
 * HPACK inflater object.
 */
typedef struct nghttp2_hd_inflater nghttp2_hd_inflater;


typedef enum {
  /* FSA accepts this state as the end of huffman encoding
     sequence. */
  NGHTTP2_HUFF_ACCEPTED = 1,
  /* This state emits symbol */
  NGHTTP2_HUFF_SYM = (1 << 1),
  /* If state machine reaches this state, decoding fails. */
  NGHTTP2_HUFF_FAIL = (1 << 2)
} nghttp2_huff_decode_flag;

#define INDEX_RANGE_VALID(context, idx)                                        \
  ((idx) < (context)->hd_table.len + NGHTTP2_STATIC_TABLE_LENGTH)


ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_inflater *inflater, nghttp2_nv *nv_out,
                              int *inflate_flags, uint8_t *in, size_t inlen,
                              int in_final);
							  
int nghttp2_hd_inflate_end_headers(nghttp2_hd_inflater *inflater);

ssize_t nghttp2_hd_inflate_hd_nv(nghttp2_hd_inflater *inflater,
                                 nghttp2_hd_nv *nv_out, int *inflate_flags,
                                 const uint8_t *in, size_t inlen,
                                 int in_final);

const char *nghttp2_strerror(int error_code);								 
uint8_t *nghttp2_cpymem(uint8_t *dest, const void *src, size_t len);
void nghttp2_mem_free(nghttp2_mem *mem, void *ptr);
void *nghttp2_mem_malloc(nghttp2_mem *mem, size_t size);
static void hd_ringbuf_pop_back(nghttp2_hd_ringbuf *ringbuf);
void nghttp2_hd_entry_free(nghttp2_hd_entry *ent);
static ssize_t decode_length(uint32_t *res, size_t *shift_ptr, int *fin,
                             uint32_t initial, size_t shift, const uint8_t *in,
                             const uint8_t *last, size_t prefix);
void nghttp2_rcbuf_incref(nghttp2_rcbuf *rcbuf);
void nghttp2_hd_entry_init(nghttp2_hd_entry *ent, nghttp2_hd_nv *nv);
void nghttp2_rcbuf_decref(nghttp2_rcbuf *rcbuf);
int32_t lookup_token(const uint8_t *name, size_t namelen);
static int hd_ringbuf_reserve(nghttp2_hd_ringbuf *ringbuf, size_t bufsize,
                              nghttp2_mem *mem);
static void hd_map_remove(nghttp2_hd_map *map, nghttp2_hd_entry *ent);
ssize_t nghttp2_hd_huff_decode(nghttp2_hd_huff_decode_context *ctx,
                               nghttp2_buf *buf, const uint8_t *src,
                               size_t srclen, int final);
static int hd_ringbuf_push_front(nghttp2_hd_ringbuf *ringbuf,
                                 nghttp2_hd_entry *ent, nghttp2_mem *mem);
static nghttp2_hd_entry *hd_ringbuf_get(nghttp2_hd_ringbuf *ringbuf,
                                        size_t idx);
static void hd_inflate_commit_indexed(nghttp2_hd_inflater *inflater,
                                      nghttp2_hd_nv *nv_out);

int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr);
#ifdef __cplusplus
}
#endif