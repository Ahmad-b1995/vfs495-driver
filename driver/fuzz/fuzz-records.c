/*
 * The record layer, which parses whatever arrives on the command endpoint. The first input
 * byte picks the parser, the rest is the data:
 *   0  vfs495_crypto_open      records of an established session
 *   1  vfs495_crypto_finish    the sensor's ChangeCipherSpec, Finished and extra record
 *   2  vfs495_crypto_key_exchange   a ServerHello
 *   3  vfs495_patch_for_sensor  a signed patch (first half) against a flash block (second half)
 */
#include <string.h>

#include "fuzz.h"
#include "vfs495-protocol.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* fixed session keys: the parsers run before and around the MAC check */
  static const guint8 premaster[48] = { 3, 0, 1, 2, 3 };
  static const guint8 cr[32] = { 1 }, sr[32] = { 2 };
  /* a ClientHello template like the command file's: 0x11, length, record */
  static const guint8 hello_tpl[63] = { 0x11, 0x3c, 0x00, 0x16, 0x03, 0x00, 0x00, 0x37, 0x01, 0x00, 0x00, 0x33, 0x03 };
  static guint8 modulus[VFS495_RSA_LEN];
  Vfs495Crypto c = { 0 };
  guint8 master[48], keyblock[136];

  if (size < 1)
    return 0;
  if (!modulus[0])
    {
      memset (modulus, 0xa5, sizeof modulus);   /* any odd 2048-bit number serves as a key */
      modulus[0] = 0x01;
    }
  switch (data[0] % 4)
    {
    case 0:
      {
        vfs495_crypto_derive (&c, premaster, cr, sr, master, keyblock);
        g_autoptr(GByteArray) out = vfs495_crypto_open (&c, data + 1, size - 1, NULL);
      }
      break;
    case 1:
      vfs495_crypto_derive (&c, premaster, cr, sr, master, keyblock);
      vfs495_crypto_finish (&c, data + 1, size - 1, NULL);
      break;
    case 2:
      {
        g_autoptr(GBytes) tpl = g_bytes_new_static (hello_tpl, sizeof hello_tpl);
        g_autoptr(GByteArray) hello = vfs495_crypto_hello (&c, tpl, NULL);
        g_autoptr(GByteArray) flight = hello ? vfs495_crypto_key_exchange (&c, data + 1, size - 1, modulus, NULL) : NULL;
      }
      break;
    case 3:
      {
        gsize half = (size - 1) / 2, out_len = 0;
        g_autofree guint8 *out = vfs495_patch_for_sensor (data + 1, half, data + 1 + half, size - 1 - half, &out_len,
                                                          NULL);
      }
      break;
    }
  vfs495_crypto_clear (&c);
  return 0;
}
