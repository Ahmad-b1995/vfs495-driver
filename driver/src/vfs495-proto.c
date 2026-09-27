#include "vfs495-proto.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string.h>

#define EP_OUT             0x01
#define EP_CMD_IN          0x81
#define EP_DATA_IN         0x82
#define DATA_CHUNK         16384
#define CMD_TIMEOUT_MS     3000
#define DATA_TIMEOUT_MS    300
#define SETUP_DATA_MS      500
#define FLASH_BLOCK_LEN    4096
#define FLASH_KEY_OFFSET   1718
#define RSA_LEN            256
#define CMD_FINGER_STATE   0x17
#define CMD_ABORT          0x04
#define POLL_PROBE_MS      40
#define POLL_INTERVAL_MS   10
#define SWIPE_QUIET_MS     300
#define SWIPE_LIMIT_S      10
#define NO_KEY             0xFFFF

/* ---- command data file ----------------------------------------------------------------- */

static void
command_free (gpointer p)
{
  Vfs495Command *c = p;

  g_bytes_unref (c->payload);
  g_free (c);
}

Vfs495Commands *
vfs495_commands_load (const char *path, GError **error)
{
  g_autofree char *data = NULL;
  gsize len, pos = 12;
  guint32 count;
  gboolean have_table = FALSE;
  Vfs495Commands *cmds;

  if (!g_file_get_contents (path, &data, &len, error))
    return NULL;
  if (len < 12 || memcmp (data, "VFS495C1", 8) != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "%s: not a VFS495 command file", path);
      return NULL;
    }
  count = GUINT32_FROM_LE (*(guint32 *) (data + 8));
  cmds = g_new0 (Vfs495Commands, 1);
  cmds->commands = g_ptr_array_new_with_free_func (command_free);
  for (guint32 i = 0; i < count; i++)
    {
      Vfs495Command *c;
      guint32 n;

      if (pos + 8 > len)
        goto truncated;
      n = GUINT32_FROM_LE (*(guint32 *) (data + pos + 4));
      if (pos + 8 + n > len)
        goto truncated;
      c = g_new0 (Vfs495Command, 1);
      c->phase = (guint8) data[pos];
      c->sends_data = ((guint8) data[pos + 1] & 1) != 0;
      c->key_offset = GUINT16_FROM_LE (*(guint16 *) (data + pos + 2));
      c->payload = g_bytes_new (data + pos + 8, n);
      pos += 8 + n;
      if (c->phase == VFS495_PHASE_DESCRAMBLE && n == sizeof cmds->descramble)
        {
          for (int k = 0; k < VFS495_LINE_WIDTH; k++)
            cmds->descramble[k] = GUINT16_FROM_LE (((guint16 *) (data + pos - n))[k]);
          have_table = TRUE;
          command_free (c);
          continue;
        }
      g_ptr_array_add (cmds->commands, c);
    }
  if (!have_table)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "%s: no descramble table", path);
      vfs495_commands_free (cmds);
      return NULL;
    }
  return cmds;

truncated:
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "%s: truncated", path);
  vfs495_commands_free (cmds);
  return NULL;
}

void
vfs495_commands_free (Vfs495Commands *cmds)
{
  if (!cmds)
    return;
  g_ptr_array_unref (cmds->commands);
  g_free (cmds);
}

/* ---- crypto primitives (Validity SSLv3 variant) ---------------------------------------- */

static void
digest (const EVP_MD *md, const guint8 *const *parts, const gsize *lens, int n, guint8 *out)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();

  EVP_DigestInit_ex (ctx, md, NULL);
  for (int i = 0; i < n; i++)
    EVP_DigestUpdate (ctx, parts[i], lens[i]);
  EVP_DigestFinal_ex (ctx, out, NULL);
  EVP_MD_CTX_free (ctx);
}

/* SSLv3 PRF: MD5(secret + SHA1(salt + secret + a + b)) with salts "A", "BB", "CCC", ... */
static void
ssl3_prf (const guint8 *secret, gsize secret_len, const guint8 *a, const guint8 *b, guint8 *out,
          gsize out_len)
{
  gsize done = 0;

  for (int i = 0; done < out_len; i++)
    {
      guint8 salt[16], sha[20], md5[16];

      memset (salt, 'A' + i, i + 1);
      {
        const guint8 *p[] = { salt, secret, a, b };
        const gsize l[] = { (gsize) i + 1, secret_len, 32, 32 };
        digest (EVP_sha1 (), p, l, 4, sha);
      }
      {
        const guint8 *p[] = { secret, sha };
        const gsize l[] = { secret_len, 20 };
        digest (EVP_md5 (), p, l, 2, md5);
      }
      memcpy (out + done, md5, MIN (16, out_len - done));
      done += 16;
    }
}

/* SSLv3 Finished: MD5 and SHA-1 halves over the handshake messages and a 4-byte label */
static void
ssl3_finished (const guint8 master[48], const guint8 *hs, gsize hs_len, const guint8 label[4],
               guint8 out[36])
{
  guint8 pad1[48], pad2[48], inner[20];

  memset (pad1, 0x36, sizeof pad1);
  memset (pad2, 0x5c, sizeof pad2);
  {
    const guint8 *p[] = { hs, label, master, pad1 };
    const gsize l[] = { hs_len, 4, 48, 48 };
    digest (EVP_md5 (), p, l, 4, inner);
  }
  {
    const guint8 *p[] = { master, pad2, inner };
    const gsize l[] = { 48, 48, 16 };
    digest (EVP_md5 (), p, l, 3, out);
  }
  {
    const guint8 *p[] = { hs, label, master, pad1 };
    const gsize l[] = { hs_len, 4, 48, 40 };
    digest (EVP_sha1 (), p, l, 4, inner);
  }
  {
    const guint8 *p[] = { master, pad2, inner };
    const gsize l[] = { 48, 40, 20 };
    digest (EVP_sha1 (), p, l, 3, out + 16);
  }
}

typedef struct
{
  guint8  mac_key[20];
  guint8  key[32];
  guint8  iv[16];
  guint64 seq;
} Direction;

/* Validity record MAC: SSLv3 SHA-1 MAC over seq + type + data (no length field) */
static void
record_mac (Direction *d, guint8 type, const guint8 *data, gsize len, guint8 out[20])
{
  guint8 pad1[40], pad2[40], hdr[9], inner[20];

  memset (pad1, 0x36, sizeof pad1);
  memset (pad2, 0x5c, sizeof pad2);
  for (int i = 0; i < 8; i++)
    hdr[i] = (guint8) (d->seq >> (56 - 8 * i));
  hdr[8] = type;
  {
    const guint8 *p[] = { d->mac_key, pad1, hdr, data };
    const gsize l[] = { 20, 40, 9, len };
    digest (EVP_sha1 (), p, l, 4, inner);
  }
  {
    const guint8 *p[] = { d->mac_key, pad2, inner };
    const gsize l[] = { 20, 40, 20 };
    digest (EVP_sha1 (), p, l, 3, out);
  }
}

static gboolean
aes_cbc (const guint8 *key, guint8 *iv, gboolean encrypt, const guint8 *in, gsize len, guint8 *out)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  int n = 0;
  gboolean ok = ctx && EVP_CipherInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv, encrypt) &&
                EVP_CIPHER_CTX_set_padding (ctx, 0) &&
                EVP_CipherUpdate (ctx, out, &n, in, (int) len) && n == (int) len;

  EVP_CIPHER_CTX_free (ctx);
  if (ok)   /* SSLv3 CBC: the last ciphertext block is the next record's IV */
    memcpy (iv, encrypt ? out + len - 16 : in + len - 16, 16);
  return ok;
}

/* type 03 00 <len BE16> <AES-CBC(data + MAC + padding)> */
static GByteArray *
record_seal (Direction *d, guint8 type, const guint8 *data, gsize len)
{
  gsize body_len = len + 20;
  gsize padlen = 16 - body_len % 16;
  g_autofree guint8 *body = g_malloc (body_len + padlen);
  GByteArray *rec = g_byte_array_sized_new (5 + body_len + padlen);
  guint8 hdr[5] = { type, 3, 0, (guint8) ((body_len + padlen) >> 8), (guint8) (body_len + padlen) };

  memcpy (body, data, len);
  record_mac (d, type, data, len, body + len);
  d->seq++;
  memset (body + body_len, (int) (padlen - 1), padlen);
  g_byte_array_append (rec, hdr, 5);
  g_byte_array_set_size (rec, 5 + body_len + padlen);
  aes_cbc (d->key, d->iv, TRUE, body, body_len + padlen, rec->data + 5);
  return rec;
}

static gboolean
record_open (Direction *d, guint8 type, const guint8 *ct, gsize len, GByteArray *out, GError **error)
{
  g_autofree guint8 *pt = g_malloc (len);
  guint8 mac[20];
  gsize padlen, body_len;

  if (len == 0 || len % 16 != 0 || !aes_cbc (d->key, d->iv, FALSE, ct, len, pt))
    goto bad;
  padlen = pt[len - 1] + 1;
  if (padlen + 20 > len)
    goto bad;
  body_len = len - padlen - 20;
  record_mac (d, type, pt, body_len, mac);
  if (memcmp (mac, pt + body_len, 20) != 0)
    goto bad;
  d->seq++;
  g_byte_array_append (out, pt, body_len);
  return TRUE;

bad:
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "bad record from sensor (seq %" G_GUINT64_FORMAT ")",
               d->seq);
  return FALSE;
}

/* RSA PKCS#1 v1.5 encryption; the sensor's modulus is stored little-endian */
static gboolean
rsa_encrypt (const guint8 modulus_le[RSA_LEN], const guint8 *msg, gsize msg_len, guint8 out[RSA_LEN],
             GError **error)
{
  BIGNUM *n = BN_lebin2bn (modulus_le, RSA_LEN, NULL);
  BIGNUM *e = BN_new ();
  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new ();
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name (NULL, "RSA", NULL);
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ectx = NULL;
  size_t out_len = RSA_LEN;
  gboolean ok = FALSE;

  BN_set_word (e, 65537);
  if (n && e && bld && kctx &&
      OSSL_PARAM_BLD_push_BN (bld, OSSL_PKEY_PARAM_RSA_N, n) &&
      OSSL_PARAM_BLD_push_BN (bld, OSSL_PKEY_PARAM_RSA_E, e) &&
      (params = OSSL_PARAM_BLD_to_param (bld)) &&
      EVP_PKEY_fromdata_init (kctx) > 0 &&
      EVP_PKEY_fromdata (kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0 &&
      (ectx = EVP_PKEY_CTX_new_from_pkey (NULL, pkey, NULL)) &&
      EVP_PKEY_encrypt_init (ectx) > 0 &&
      EVP_PKEY_CTX_set_rsa_padding (ectx, RSA_PKCS1_PADDING) > 0 &&
      EVP_PKEY_encrypt (ectx, out, &out_len, msg, msg_len) > 0 && out_len == RSA_LEN)
    ok = TRUE;
  else
    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "RSA encryption failed");

  EVP_PKEY_CTX_free (ectx);
  EVP_PKEY_free (pkey);
  EVP_PKEY_CTX_free (kctx);
  OSSL_PARAM_free (params);
  OSSL_PARAM_BLD_free (bld);
  BN_free (e);
  BN_free (n);
  return ok;
}

/* ---- session --------------------------------------------------------------------------- */

struct _Vfs495Session
{
  GUsbDevice           *usb;
  const Vfs495Commands *cmds;
  Direction             client;
  Direction             server;
  gboolean              open;
  gboolean              captured;      /* a capture ran since setup: re-arm before arming */
  guint8                image_key[32];
  guint8                image_iv[16];
};

Vfs495Session *
vfs495_session_new (GUsbDevice *usb, const Vfs495Commands *cmds)
{
  Vfs495Session *s = g_new0 (Vfs495Session, 1);

  s->usb = g_object_ref (usb);
  s->cmds = cmds;
  return s;
}

void
vfs495_session_free (Vfs495Session *s)
{
  if (!s)
    return;
  g_object_unref (s->usb);
  explicit_bzero (s, sizeof *s);
  g_free (s);
}

static gboolean
usb_write (Vfs495Session *s, const guint8 *data, gsize len, GError **error)
{
  gsize actual = 0;

  if (!g_usb_device_bulk_transfer (s->usb, EP_OUT, (guint8 *) data, len, &actual, CMD_TIMEOUT_MS, NULL, error))
    return FALSE;
  if (actual != len)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "short write (%zu of %zu)", actual, len);
      return FALSE;
    }
  return TRUE;
}

static GByteArray *
usb_read_cmd (Vfs495Session *s, guint timeout, GError **error)
{
  GByteArray *buf = g_byte_array_sized_new (DATA_CHUNK);
  gsize actual = 0;

  g_byte_array_set_size (buf, DATA_CHUNK);
  if (!g_usb_device_bulk_transfer (s->usb, EP_CMD_IN, buf->data, DATA_CHUNK, &actual, timeout, NULL, error))
    {
      g_byte_array_unref (buf);
      return NULL;
    }
  g_byte_array_set_size (buf, actual);
  return buf;
}

static gboolean
is_timeout (const GError *e)
{
  return g_error_matches (e, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT);
}

/*
 * Read the data endpoint. until_short: stop at a short transfer (setup data); otherwise stop
 * after `quiet` ms without data or `limit_s` seconds (swipe streams have short transfers
 * mid-stream). A timeout before any data just ends the read.
 */
static gboolean
usb_read_data (Vfs495Session *s, gboolean until_short, guint quiet, guint limit_s, GByteArray *out,
               GError **error)
{
  gint64 end = g_get_monotonic_time () + (gint64) limit_s * G_USEC_PER_SEC;
  guint8 *chunk = g_malloc (DATA_CHUNK);

  while (g_get_monotonic_time () < end)
    {
      g_autoptr(GError) local = NULL;
      gsize actual = 0;

      if (!g_usb_device_bulk_transfer (s->usb, EP_DATA_IN, chunk, DATA_CHUNK, &actual, quiet, NULL, &local))
        {
          if (is_timeout (local))
            break;
          g_propagate_error (error, g_steal_pointer (&local));
          g_free (chunk);
          return FALSE;
        }
      g_byte_array_append (out, chunk, actual);
      if (until_short && actual < DATA_CHUNK)
        break;
    }
  g_free (chunk);
  return TRUE;
}

static gboolean
drain_setup_data (Vfs495Session *s, GByteArray *out, GError **error)
{
  return usb_read_data (s, TRUE, SETUP_DATA_MS, 5, out, error);
}

/* decrypt every record of a reply */
static GByteArray *
open_records (Vfs495Session *s, const GByteArray *resp, gsize start, GError **error)
{
  GByteArray *out = g_byte_array_new ();
  gsize pos = start;

  while (pos + 5 <= resp->len)
    {
      gsize n = (gsize) resp->data[pos + 3] << 8 | resp->data[pos + 4];

      if (pos + 5 + n > resp->len ||
          !record_open (&s->server, resp->data[pos], resp->data + pos + 5, n, out, error))
        {
          if (error && !*error)
            g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "truncated record");
          g_byte_array_unref (out);
          return NULL;
        }
      pos += 5 + n;
    }
  return out;
}

/* encrypted command; returns the decrypted reply (status u16 LE + data) */
static GByteArray *
session_cmd (Vfs495Session *s, const guint8 *payload, gsize len, guint timeout, GError **error)
{
  g_autoptr(GByteArray) rec = record_seal (&s->client, 0x17, payload, len);
  g_autoptr(GByteArray) resp = NULL;

  if (!usb_write (s, rec->data, rec->len, error))
    return NULL;
  resp = usb_read_cmd (s, timeout, error);
  if (!resp)
    return NULL;
  return open_records (s, resp, 0, error);
}

static gboolean
check_status (const GByteArray *reply, guint8 cmd, GError **error)
{
  if (reply->len < 2 || reply->data[0] != 0 || reply->data[1] != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "sensor refused command %02x (status %02x%02x)", cmd,
                   reply->len > 1 ? reply->data[1] : 0xff, reply->len > 0 ? reply->data[0] : 0xff);
      return FALSE;
    }
  return TRUE;
}

static gboolean
handshake (Vfs495Session *s, const guint8 modulus[RSA_LEN], GBytes *hello_tpl, GError **error)
{
  gsize tpl_len;
  const guint8 *tpl = g_bytes_get_data (hello_tpl, &tpl_len);
  g_autofree guint8 *rec_ch = g_memdup2 (tpl + 3, tpl_len - 3);
  gsize ch_len = tpl_len - 3;
  guint8 client_random[32], premaster[48], enc[RSA_LEN], master[48], keyblock[136], fin[36];
  g_autoptr(GByteArray) sh = NULL;
  g_autoptr(GByteArray) msg = g_byte_array_new ();
  g_autoptr(GByteArray) hs = g_byte_array_new ();
  g_autoptr(GByteArray) flight = g_byte_array_new ();
  g_autoptr(GByteArray) fin_rec = NULL;
  g_autoptr(GByteArray) resp = NULL;
  g_autoptr(GByteArray) extra = NULL;
  guint8 cke_hs[4 + RSA_LEN] = { 0x10, 0x00, 0x01, 0x00 };
  guint8 fin_hs[4 + 36] = { 0x14, 0x00, 0x00, 0x24 };
  const guint8 label[4] = { 0x54, 0x4e, 0x4c, 0x43 };   /* 0x434C4E54 little-endian */
  const guint8 ccs[6] = { 0x14, 0x03, 0x00, 0x00, 0x01, 0x01 };
  gsize sh_hs_len, pos;

  if (RAND_bytes (client_random, 32) != 1 || RAND_bytes (premaster + 2, 46) != 1)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "no randomness");
      return FALSE;
    }
  premaster[0] = 0x03;
  premaster[1] = 0x00;
  memcpy (rec_ch + 11, client_random, 32);
  if (!rsa_encrypt (modulus, premaster, sizeof premaster, enc, error))
    return FALSE;
  memcpy (cke_hs + 4, enc, RSA_LEN);

  /* ClientHello, tunnelled in command 0x11 */
  {
    guint8 hdr[3] = { 0x11, (guint8) ch_len, (guint8) (ch_len >> 8) };
    g_byte_array_append (msg, hdr, 3);
    g_byte_array_append (msg, rec_ch, ch_len);
  }
  if (!usb_write (s, msg->data, msg->len, error))
    return FALSE;
  sh = usb_read_cmd (s, CMD_TIMEOUT_MS, error);
  if (!sh)
    return FALSE;
  if (sh->len < 43 || sh->data[0] != 0x16)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "no ServerHello from sensor");
      return FALSE;
    }
  sh_hs_len = (gsize) sh->data[3] << 8 | sh->data[4];

  ssl3_prf (premaster, 48, client_random, sh->data + 11, master, 48);
  ssl3_prf (master, 48, sh->data + 11, client_random, keyblock, 136);
  memcpy (s->client.mac_key, keyblock, 20);
  memcpy (s->server.mac_key, keyblock + 20, 20);
  memcpy (s->client.key, keyblock + 40, 32);
  memcpy (s->server.key, keyblock + 72, 32);
  memcpy (s->client.iv, keyblock + 104, 16);
  memcpy (s->server.iv, keyblock + 120, 16);
  s->client.seq = s->server.seq = 0;

  g_byte_array_append (hs, rec_ch + 5, ch_len - 5);
  g_byte_array_append (hs, sh->data + 5, MIN (sh_hs_len, sh->len - 5));
  g_byte_array_append (hs, cke_hs, sizeof cke_hs);
  ssl3_finished (master, hs->data, hs->len, label, fin);
  memcpy (fin_hs + 4, fin, 36);
  fin_rec = record_seal (&s->client, 0x16, fin_hs, sizeof fin_hs);

  {
    guint8 cke_hdr[5] = { 0x16, 0x03, 0x00, (guint8) (sizeof cke_hs >> 8), (guint8) sizeof cke_hs };
    gsize flen = 5 + sizeof cke_hs + sizeof ccs + fin_rec->len;
    guint8 hdr[3] = { 0x11, (guint8) flen, (guint8) (flen >> 8) };
    g_byte_array_append (flight, hdr, 3);
    g_byte_array_append (flight, cke_hdr, 5);
    g_byte_array_append (flight, cke_hs, sizeof cke_hs);
    g_byte_array_append (flight, ccs, sizeof ccs);
    g_byte_array_append (flight, fin_rec->data, fin_rec->len);
  }
  if (!usb_write (s, flight->data, flight->len, error))
    return FALSE;
  resp = usb_read_cmd (s, CMD_TIMEOUT_MS, error);
  if (!resp)
    return FALSE;
  if (resp->len < 6 || resp->data[0] != 0x14)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "sensor rejected the handshake (%02x %02x)",
                   resp->len > 0 ? resp->data[0] : 0, resp->len > 6 ? resp->data[resp->len - 1] : 0);
      return FALSE;
    }
  /* CCS, then the encrypted server Finished (seq 0) and one unsolicited record (seq 1) */
  pos = 6;
  extra = open_records (s, resp, pos, error);
  explicit_bzero (premaster, sizeof premaster);
  explicit_bzero (master, sizeof master);
  explicit_bzero (keyblock, sizeof keyblock);
  return extra != NULL;
}

gboolean
vfs495_session_open (Vfs495Session *s, GError **error)
{
  g_autoptr(GByteArray) flash = NULL;
  GBytes *hello = NULL;

  s->open = FALSE;
  s->captured = FALSE;
  for (guint i = 0; i < s->cmds->commands->len; i++)
    {
      Vfs495Command *c = g_ptr_array_index (s->cmds->commands, i);
      gsize len;
      const guint8 *p = g_bytes_get_data (c->payload, &len);

      if (c->phase == VFS495_PHASE_PRE)
        {
          g_autoptr(GByteArray) reply = NULL;
          g_autoptr(GByteArray) data = g_byte_array_new ();

          if (!usb_write (s, p, len, error) || !(reply = usb_read_cmd (s, CMD_TIMEOUT_MS, error)))
            return FALSE;
          if (c->sends_data && !drain_setup_data (s, data, error))
            return FALSE;
          g_debug ("pre-session %02x: reply %u bytes, data %u bytes", p[0], reply->len, data->len);
          if (data->len == FLASH_BLOCK_LEN)
            flash = g_byte_array_ref (data);
        }
      else if (c->phase == VFS495_PHASE_HELLO)
        {
          hello = c->payload;
          if (!flash)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "sensor key not found in flash");
              return FALSE;
            }
          if (!handshake (s, flash->data + FLASH_KEY_OFFSET, hello, error))
            return FALSE;
        }
      else if (c->phase == VFS495_PHASE_SETUP)
        {
          g_autoptr(GByteArray) reply = session_cmd (s, p, len, CMD_TIMEOUT_MS, error);
          g_autoptr(GByteArray) data = g_byte_array_new ();

          if (!reply || !check_status (reply, p[0], error))
            return FALSE;
          if (c->sends_data && !drain_setup_data (s, data, error))
            return FALSE;
        }
    }
  s->open = TRUE;
  return TRUE;
}

gboolean
vfs495_session_arm (Vfs495Session *s, GError **error)
{
  for (guint i = 0; i < s->cmds->commands->len; i++)
    {
      Vfs495Command *c = g_ptr_array_index (s->cmds->commands, i);
      gsize len;
      const guint8 *p = g_bytes_get_data (c->payload, &len);
      g_autofree guint8 *payload = NULL;
      g_autoptr(GByteArray) reply = NULL;
      g_autoptr(GByteArray) data = g_byte_array_new ();

      if (!(c->phase == VFS495_PHASE_ARM || (c->phase == VFS495_PHASE_REARM && s->captured)))
        continue;
      payload = g_memdup2 (p, len);
      if (c->phase == VFS495_PHASE_ARM)
        {
          if (c->key_offset == NO_KEY || (gsize) c->key_offset + 64 > len ||
              RAND_bytes (s->image_key, 32) != 1 || RAND_bytes (s->image_iv, 16) != 1 ||
              RAND_bytes (payload + c->key_offset + 48, 16) != 1)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "cannot set the image key");
              return FALSE;
            }
          memcpy (payload + c->key_offset, s->image_key, 32);
          memcpy (payload + c->key_offset + 32, s->image_iv, 16);
        }
      reply = session_cmd (s, payload, len, CMD_TIMEOUT_MS, error);
      explicit_bzero (payload, len);
      if (!reply || !check_status (reply, p[0], error))
        return FALSE;
      if (c->sends_data && !drain_setup_data (s, data, error))
        return FALSE;
    }
  s->captured = TRUE;
  return TRUE;
}

void
vfs495_session_image_key (Vfs495Session *s, guint8 key[32], guint8 iv[16])
{
  memcpy (key, s->image_key, 32);
  memcpy (iv, s->image_iv, 16);
}

/* abort a capture; the sensor pushes pending data before it replies, so drain first */
static gboolean
abort_capture (Vfs495Session *s, GError **error)
{
  const guint8 cmd = CMD_ABORT;
  g_autoptr(GByteArray) rec = record_seal (&s->client, 0x17, &cmd, 1);
  g_autoptr(GByteArray) data = g_byte_array_new ();
  g_autoptr(GByteArray) resp = NULL;
  g_autoptr(GByteArray) reply = NULL;

  if (!usb_write (s, rec->data, rec->len, error) ||
      !usb_read_data (s, TRUE, SETUP_DATA_MS, 5, data, error) ||
      !(resp = usb_read_cmd (s, CMD_TIMEOUT_MS, error)))
    return FALSE;
  reply = open_records (s, resp, 0, error);
  return reply != NULL;
}

gboolean
vfs495_session_wait_swipe (Vfs495Session *s, GCancellable *cancellable, GByteArray **stream,
                           GError **error)
{
  const guint8 poll = CMD_FINGER_STATE;
  g_autoptr(GByteArray) out = g_byte_array_new ();
  guint8 *chunk = g_malloc (DATA_CHUNK);
  gboolean ok = TRUE;

  *stream = NULL;
  while (TRUE)
    {
      g_autoptr(GByteArray) state = NULL;
      g_autoptr(GError) local = NULL;
      gsize actual = 0;

      if (g_cancellable_is_cancelled (cancellable))
        break;
      state = session_cmd (s, &poll, 1, CMD_TIMEOUT_MS, error);
      if (!state || !check_status (state, poll, error))
        {
          ok = FALSE;
          break;
        }
      /* byte 0 after the status becomes 02 when a capture starts; also probe the data
       * endpoint, and never send another command while the sensor may be streaming */
      if (g_usb_device_bulk_transfer (s->usb, EP_DATA_IN, chunk, DATA_CHUNK, &actual, POLL_PROBE_MS, NULL, &local))
        g_byte_array_append (out, chunk, actual);
      else if (!is_timeout (local))
        {
          g_propagate_error (error, g_steal_pointer (&local));
          ok = FALSE;
          break;
        }
      if (out->len > 0 || (state->len > 2 && state->data[2] != 0))
        {
          ok = usb_read_data (s, FALSE, SWIPE_QUIET_MS, SWIPE_LIMIT_S, out, error);
          break;
        }
      g_usleep (POLL_INTERVAL_MS * 1000);
    }
  g_free (chunk);

  {
    g_autoptr(GError) abort_error = NULL;
    if (!abort_capture (s, ok ? error : &abort_error))
      ok = FALSE;
  }
  if (!ok)
    return FALSE;
  if (out->len == 0 && g_cancellable_is_cancelled (cancellable))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "cancelled");
      return FALSE;
    }
  *stream = g_steal_pointer (&out);
  return TRUE;
}

void
vfs495_session_close (Vfs495Session *s)
{
  const guint8 notify[2] = { 0x01, 0x00 };
  g_autoptr(GByteArray) rec = NULL;
  g_autoptr(GByteArray) resp = NULL;

  if (!s->open)
    return;
  rec = record_seal (&s->client, 0x15, notify, 2);
  if (usb_write (s, rec->data, rec->len, NULL))
    resp = usb_read_cmd (s, 1000, NULL);
  s->open = FALSE;
}
