#include "vfs495-protocol.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string.h>

#define RSA_LEN VFS495_RSA_LEN

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


/* Validity record MAC: SSLv3 SHA-1 MAC over seq + type + data (no length field) */
static void
record_mac (Vfs495Direction *d, guint8 type, const guint8 *data, gsize len, guint8 out[20])
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
record_seal (Vfs495Direction *d, guint8 type, const guint8 *data, gsize len)
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
record_open (Vfs495Direction *d, guint8 type, const guint8 *ct, gsize len, GByteArray *out, GError **error)
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

/* ---- randomness ------------------------------------------------------------------------ */

static gboolean deterministic;
static guint64  deterministic_counter;

void
vfs495_random_set_deterministic (gboolean on)
{
  deterministic = on;
  deterministic_counter = 0;
}

gboolean
vfs495_random (guint8 *buf, gsize len)
{
  if (!deterministic)
    return RAND_bytes (buf, (int) len) == 1;
  /* SHA-256 of a label and a counter: the same bytes in every run */
  for (gsize done = 0; done < len; done += 32)
    {
      guint8 block[32], ctr[8];
      const guint8 label[] = "vfs495 emulation";

      for (int i = 0; i < 8; i++)
        ctr[i] = (guint8) (deterministic_counter >> (56 - 8 * i));
      deterministic_counter++;
      {
        const guint8 *p[] = { label, ctr };
        const gsize l[] = { sizeof label - 1, 8 };
        digest (EVP_sha256 (), p, l, 2, block);
      }
      memcpy (buf + done, block, MIN (32, len - done));
    }
  return TRUE;
}

/* RSA PKCS#1 v1.5 encryption; the sensor's modulus is stored little-endian. The padding is
 * built here (00 02, non-zero random bytes, 00, message) and the RSA operation done raw, so the
 * padding comes from vfs495_random like every other random value of a session. */
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
  guint8 em[RSA_LEN];
  gsize ps_len = RSA_LEN - 3 - msg_len;
  size_t out_len = RSA_LEN;
  gboolean ok = FALSE;

  em[0] = 0x00;
  em[1] = 0x02;
  ok = msg_len <= RSA_LEN - 11 && vfs495_random (em + 2, ps_len);
  for (gsize i = 2; ok && i < 2 + ps_len; i++)
    while (ok && em[i] == 0)
      ok = vfs495_random (em + i, 1);
  em[2 + ps_len] = 0x00;
  if (ok)
    memcpy (em + 3 + ps_len, msg, msg_len);

  BN_set_word (e, 65537);
  if (ok && n && e && bld && kctx &&
      OSSL_PARAM_BLD_push_BN (bld, OSSL_PKEY_PARAM_RSA_N, n) &&
      OSSL_PARAM_BLD_push_BN (bld, OSSL_PKEY_PARAM_RSA_E, e) &&
      (params = OSSL_PARAM_BLD_to_param (bld)) &&
      EVP_PKEY_fromdata_init (kctx) > 0 &&
      EVP_PKEY_fromdata (kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) > 0 &&
      (ectx = EVP_PKEY_CTX_new_from_pkey (NULL, pkey, NULL)) &&
      EVP_PKEY_encrypt_init (ectx) > 0 &&
      EVP_PKEY_CTX_set_rsa_padding (ectx, RSA_NO_PADDING) > 0 &&
      EVP_PKEY_encrypt (ectx, out, &out_len, em, RSA_LEN) > 0 && out_len == RSA_LEN)
    ok = TRUE;
  else
    {
      ok = FALSE;
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "RSA encryption failed");
    }

  explicit_bzero (em, sizeof em);
  EVP_PKEY_CTX_free (ectx);
  EVP_PKEY_free (pkey);
  OSSL_PARAM_free (params);
  OSSL_PARAM_BLD_free (bld);
  BN_free (e);
  BN_free (n);
  return ok;
}

/* ---- session setup and records --------------------------------------------------------- */

void
vfs495_crypto_clear (Vfs495Crypto *c)
{
  g_clear_pointer (&c->hello, g_byte_array_unref);
  explicit_bzero (c, sizeof *c);
}

GByteArray *
vfs495_crypto_hello (Vfs495Crypto *c, GBytes *hello_template, GError **error)
{
  gsize tpl_len;
  const guint8 *tpl = g_bytes_get_data (hello_template, &tpl_len);
  GByteArray *msg;
  gsize ch_len;

  vfs495_crypto_clear (c);
  if (tpl_len < 3 + 11 + 32)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "ClientHello template too short");
      return NULL;
    }
  if (!vfs495_random (c->client_random, 32) || !vfs495_random (c->premaster + 2, 46))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "no randomness");
      return NULL;
    }
  c->premaster[0] = 0x03;
  c->premaster[1] = 0x00;

  /* command 0x11, u16 LE length, then the ClientHello record with our random */
  ch_len = tpl_len - 3;
  msg = g_byte_array_sized_new (tpl_len);
  {
    guint8 hdr[3] = { 0x11, (guint8) ch_len, (guint8) (ch_len >> 8) };
    g_byte_array_append (msg, hdr, 3);
  }
  g_byte_array_append (msg, tpl + 3, ch_len);
  memcpy (msg->data + 3 + 11, c->client_random, 32);
  c->hello = g_byte_array_new ();
  g_byte_array_append (c->hello, msg->data + 3 + 5, ch_len - 5);   /* handshake message only */
  return msg;
}

void
vfs495_crypto_derive (Vfs495Crypto *c, const guint8 premaster[48], const guint8 client_random[32],
                      const guint8 server_random[32], guint8 master[48], guint8 keyblock[136])
{
  ssl3_prf (premaster, 48, client_random, server_random, master, 48);
  ssl3_prf (master, 48, server_random, client_random, keyblock, 136);
  memcpy (c->client.mac_key, keyblock, 20);
  memcpy (c->server.mac_key, keyblock + 20, 20);
  memcpy (c->client.key, keyblock + 40, 32);
  memcpy (c->server.key, keyblock + 72, 32);
  memcpy (c->client.iv, keyblock + 104, 16);
  memcpy (c->server.iv, keyblock + 120, 16);
  c->client.seq = c->server.seq = 0;
}

void
vfs495_crypto_finished (const guint8 master[48], const guint8 *handshake, gsize len, guint8 out[36])
{
  const guint8 label[4] = { 0x54, 0x4e, 0x4c, 0x43 };   /* 0x434C4E54 little-endian */

  ssl3_finished (master, handshake, len, label, out);
}

GByteArray *
vfs495_crypto_key_exchange (Vfs495Crypto *c, const guint8 *sh, gsize sh_len, const guint8 modulus_le[RSA_LEN],
                            GError **error)
{
  guint8 enc[RSA_LEN], master[48], keyblock[136], fin[36];
  guint8 cke_hs[4 + RSA_LEN] = { 0x10, 0x00, 0x01, 0x00 };
  guint8 fin_hs[4 + 36] = { 0x14, 0x00, 0x00, 0x24 };
  const guint8 ccs[6] = { 0x14, 0x03, 0x00, 0x00, 0x01, 0x01 };
  const guint8 *server_random = sh + 11;
  g_autoptr(GByteArray) hs = g_byte_array_new ();
  g_autoptr(GByteArray) fin_rec = NULL;
  GByteArray *flight;
  gsize sh_hs_len;

  if (!c->hello)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "no ClientHello sent");
      return NULL;
    }
  if (sh_len < 43 || sh[0] != 0x16)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "no ServerHello from sensor");
      return NULL;
    }
  sh_hs_len = (gsize) sh[3] << 8 | sh[4];
  if (!rsa_encrypt (modulus_le, c->premaster, sizeof c->premaster, enc, error))
    return NULL;
  memcpy (cke_hs + 4, enc, RSA_LEN);

  vfs495_crypto_derive (c, c->premaster, c->client_random, server_random, master, keyblock);

  g_byte_array_append (hs, c->hello->data, c->hello->len);
  g_byte_array_append (hs, sh + 5, MIN (sh_hs_len, sh_len - 5));
  g_byte_array_append (hs, cke_hs, sizeof cke_hs);
  vfs495_crypto_finished (master, hs->data, hs->len, fin);
  memcpy (fin_hs + 4, fin, 36);
  fin_rec = record_seal (&c->client, 0x16, fin_hs, sizeof fin_hs);

  flight = g_byte_array_new ();
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
  explicit_bzero (c->premaster, sizeof c->premaster);
  explicit_bzero (master, sizeof master);
  explicit_bzero (keyblock, sizeof keyblock);
  return flight;
}

GByteArray *
vfs495_crypto_open (Vfs495Crypto *c, const guint8 *reply, gsize len, GError **error)
{
  GByteArray *out = g_byte_array_new ();
  gsize pos = 0;

  while (pos + 5 <= len)
    {
      gsize n = (gsize) reply[pos + 3] << 8 | reply[pos + 4];

      if (pos + 5 + n > len)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "truncated record");
          g_byte_array_unref (out);
          return NULL;
        }
      if (!record_open (&c->server, reply[pos], reply + pos + 5, n, out, error))
        {
          g_byte_array_unref (out);
          return NULL;
        }
      pos += 5 + n;
    }
  return out;
}

gboolean
vfs495_crypto_finish (Vfs495Crypto *c, const guint8 *reply, gsize len, GError **error)
{
  g_autoptr(GByteArray) extra = NULL;

  if (len < 6 || reply[0] != 0x14)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "sensor rejected the handshake (%02x %02x)",
                   len > 0 ? reply[0] : 0, len > 6 ? reply[len - 1] : 0);
      return FALSE;
    }
  /* CCS (6 bytes), then the encrypted server Finished (seq 0) and one unsolicited record */
  extra = vfs495_crypto_open (c, reply + 6, len - 6, error);
  g_clear_pointer (&c->hello, g_byte_array_unref);
  explicit_bzero (c->client_random, sizeof c->client_random);
  return extra != NULL;
}

GByteArray *
vfs495_crypto_seal (Vfs495Crypto *c, guint8 type, const guint8 *data, gsize len)
{
  return record_seal (&c->client, type, data, len);
}

gboolean
vfs495_check_status (const guint8 *reply, gsize len, guint8 cmd, GError **error)
{
  if (len < 2 || reply[0] != 0 || reply[1] != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "sensor refused command %02x (status %02x%02x)", cmd,
                   len > 1 ? reply[1] : 0xff, len > 0 ? reply[0] : 0xff);
      return FALSE;
    }
  return TRUE;
}

char *
vfs495_hex_prefix (const guint8 *data, gsize len, gsize max)
{
  GString *out = g_string_new (NULL);

  for (gsize i = 0; i < MIN (len, max); i++)
    g_string_append_printf (out, "%02x", data[i]);
  return g_string_free (out, FALSE);
}

guint8 *
vfs495_patch_for_sensor (const guint8 *payload, gsize len, const guint8 *flash, gsize flash_len, gsize *out_len,
                         GError **error)
{
  const gsize label_len = 8, hmac_len = 32, rsa_len = 256;
  const guint8 *patch = payload + label_len;
  gsize patch_len = len - label_len;
  guint8 *out;

  if (len < label_len + 5 + rsa_len || patch[0] != 0x06 || patch[1] != 0x02 || patch[3] != 0x00 || patch[4] != 0x01)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "not a signed patch");
      return NULL;
    }
  for (gsize i = 0; flash && i + label_len + hmac_len <= flash_len; i++)
    if (memcmp (flash + i, payload, label_len) == 0)
      {
        /* 06 | 02 00 | 20 00 | HMAC | body */
        *out_len = 5 + hmac_len + (patch_len - 5 - rsa_len);
        out = g_malloc (*out_len);
        memcpy (out, patch, 3);
        out[3] = (guint8) hmac_len;
        out[4] = 0x00;
        memcpy (out + 5, flash + i + label_len, hmac_len);
        memcpy (out + 5 + hmac_len, patch + 5 + rsa_len, patch_len - 5 - rsa_len);
        return out;
      }
  g_debug ("no cached signature for patch %02x%02x%02x%02x v%u in flash: sending it RSA-signed", payload[3],
           payload[2], payload[1], payload[0], payload[4]);
  *out_len = patch_len;
  return g_memdup2 (patch, patch_len);
}
