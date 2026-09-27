/*
 * VFS495 swipe stream decoding: AES-256-CBC decryption with the key the host chose when
 * arming, then 272-byte frames (`01 fe <seq u16> <4 bytes>` + 264 pixels in sensor column
 * order), descrambled with the table from the command data file.
 */
#pragma once

#include <gio/gio.h>

#include "vfs495-assemble.h"

/*
 * Returns n_lines x VFS495_LINE_WIDTH descrambled pixels (newly allocated), or NULL with error
 * set. descramble maps sensor column i to image column descramble[i].
 */
guint8 *vfs495_decode_stream (const guint8  *stream,
                              gsize          len,
                              const guint8   key[32],
                              const guint8   iv[16],
                              const guint16 *descramble,
                              int           *n_lines,
                              GError       **error);
