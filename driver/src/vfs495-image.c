#include "vfs495-image.h"

#include <openssl/evp.h>
#include <string.h>

#define FRAME   272
#define HEADER  8

guint8 *
vfs495_frames_to_lines (const guint8 *plain, gsize len, const guint16 *descramble, int *n_lines,
                        Vfs495DecodeInfo *info)
{
  GByteArray *lines = g_byte_array_new ();
  guint frames = 0, gaps = 0, stray = 0;
  guint16 last_seq = 0;
  gsize i = 0;

  while (i + FRAME <= len)
    {
      if (plain[i] == 0x01 && plain[i + 1] == 0xfe)
        {
          guint8 line[VFS495_LINE_WIDTH];
          guint16 seq = (guint16) (plain[i + 2] | plain[i + 3] << 8);

          if (frames++ > 0 && seq != (guint16) (last_seq + 1))
            gaps++;
          last_seq = seq;
          for (int k = 0; k < VFS495_LINE_WIDTH; k++)
            line[descramble[k]] = plain[i + HEADER + k];
          g_byte_array_append (lines, line, VFS495_LINE_WIDTH);
          i += FRAME;
        }
      else
        {
          i++;
          stray++;
        }
    }
  g_debug ("decoded %u frames, %u sequence gaps, %u stray bytes", frames, gaps, stray);
  if (info)
    *info = (Vfs495DecodeInfo) { frames, gaps, stray };
  *n_lines = (int) (lines->len / VFS495_LINE_WIDTH);
  return g_byte_array_free (lines, FALSE);
}

guint8 *
vfs495_decrypt_stream (const guint8 *stream, gsize len, const guint8 key[32], const guint8 iv[16], gsize *plain_len,
                       GError **error)
{
  gsize usable = len - len % 16;
  guint8 *plain;
  EVP_CIPHER_CTX *ctx;
  int out_len = 0;
  gboolean ok;

  if (usable > G_MAXINT - 16)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "image stream too long");
      return NULL;
    }
  plain = g_malloc (usable + 16);
  ctx = EVP_CIPHER_CTX_new ();
  ok = ctx && EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv) && EVP_CIPHER_CTX_set_padding (ctx, 0) &&
       EVP_DecryptUpdate (ctx, plain, &out_len, stream, (int) usable);
  EVP_CIPHER_CTX_free (ctx);
  if (!ok)
    {
      g_free (plain);
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "image decryption failed");
      return NULL;
    }
  *plain_len = (gsize) out_len;
  return plain;
}

guint8 *
vfs495_decode_stream (const guint8 *stream, gsize len, const guint8 key[32], const guint8 iv[16],
                      const guint16 *descramble, int *n_lines, Vfs495DecodeInfo *info, GError **error)
{
  gsize plain_len;
  g_autofree guint8 *plain = vfs495_decrypt_stream (stream, len, key, iv, &plain_len, error);

  if (!plain)
    return NULL;
  return vfs495_frames_to_lines (plain, plain_len, descramble, n_lines, info);
}
