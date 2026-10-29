/*
 * Tests that need no recorded data: the stitcher on simulated swipes (vfs495-sim.h), the swipe
 * stream decoder, the command file parser, the session crypto against a locally generated RSA
 * key, signed patches and the beta diagnostics. Run by `meson test` and in CI; the tests on
 * recorded data are in vfs495-test.c.
 */
#include <glib/gstdio.h>
#include <math.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

#include "vfs495-assemble.h"
#include "vfs495-commands.h"
#include "vfs495-diag.h"
#include "vfs495-image.h"
#include "vfs495-protocol.h"
#include "vfs495-sim.h"

/* ---- stitcher on simulated swipes ----------------------------------------------------- */

typedef struct
{
  Vfs495SwipeVerdict verdict;
  Vfs495AssembleInfo info;
  guint8            *image;
  SimMatch           match;
} Swiped;

static Swiped
swipe (guint32 seed, const SimSwipe *s)
{
  g_autoptr(SimFinger) f = sim_finger_new (seed, 600);
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *lines = NULL;
  Swiped out = { 0 };
  int n;

  lines = sim_swipe_lines (f, s, &n);
  out.image = vfs495_assemble (lines, n, &out.info, &error);
  out.verdict = vfs495_swipe_verdict (out.image, &out.info);
  if (out.image)
    out.match = sim_match (f, out.image, out.info.rows);
  g_test_message ("seed %u: %d lines, %s, rows %d, region %d, lag %.1f, fast %.2f, still %.2f, coverage %.2f, "
                  "bad columns %d, correlation %.2f, scale %.3f", seed, n, vfs495_swipe_verdict_name (out.verdict),
                  out.info.rows, out.info.region_lines, out.info.median_lag, out.info.fast, out.info.still_fraction,
                  out.info.coverage, out.info.bad_columns, out.match.correlation, out.match.scale);
  return out;
}

static void
test_assemble_normal (void)
{
  for (guint32 seed = 1; seed <= 4; seed++)
    {
      SimSwipe s = sim_swipe_default ();
      Swiped r;

      s.seed = seed;
      r = swipe (seed, &s);
      g_assert_cmpint (r.verdict, ==, VFS495_SWIPE_OK);
      /* the finger moved 0.3 px per line: a ridge needs 8 / 0.3 = 26.7 lines between the lines */
      g_assert_cmpfloat (fabs (r.info.median_lag - SIM_LINE_DISTANCE / 0.3), <=, 2.0);
      /* nearly all of the 560 rows that passed, at the right scale */
      g_assert_cmpint (r.info.rows, >=, 480);
      g_assert_cmpfloat (r.info.coverage, >=, 0.85);
      g_assert_cmpfloat (r.match.correlation, >=, 0.6);
      g_assert_cmpfloat (fabs (r.match.scale - 1), <=, 0.15);
      g_free (r.image);
    }
}

static void
test_assemble_speed_change (void)
{
  for (guint32 seed = 1; seed <= 3; seed++)
    {
      SimSwipe s = sim_swipe_default ();
      Swiped r;

      s.seed = seed;
      s.speed_start = 0.15;
      s.speed_end = 0.6;
      r = swipe (seed, &s);
      g_assert_cmpint (r.verdict, ==, VFS495_SWIPE_OK);
      g_assert_cmpfloat (r.info.median_lag, >=, SIM_LINE_DISTANCE / 0.6);
      g_assert_cmpfloat (r.info.median_lag, <=, SIM_LINE_DISTANCE / 0.15);
      g_assert_cmpint (r.info.rows, >=, 480);
      g_assert_cmpfloat (r.match.correlation, >=, 0.6);
      g_assert_cmpfloat (fabs (r.match.scale - 1), <=, 0.15);
      g_free (r.image);
    }
}

static void
test_assemble_verdicts (void)
{
  struct
  {
    const char        *name;
    double             speed, travel, start;
    int                rest, right;
    Vfs495SwipeVerdict want;
  } cases[] = {
    /* faster than the 8 lines of lag the stitcher trusts: 1.5 px per line is a 5-line lag */
    { "too fast", 1.5, 560, 20, 0, VFS495_MAIN_WIDTH, VFS495_SWIPE_TOO_FAST },
    /* the finger over the left 90 columns only */
    { "off centre", 0.3, 560, 20, 0, 90, VFS495_SWIPE_OFF_CENTRE },
    /* resting where ridges cross the line, then lifted */
    { "resting", 0.3, 0.5, 300, 800, VFS495_MAIN_WIDTH, VFS495_SWIPE_RESTING },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    for (guint32 seed = 1; seed <= 4; seed++)
      {
        SimSwipe s = sim_swipe_default ();
        Swiped r;

        g_test_message ("%s", cases[i].name);
        s.seed = seed;
        s.speed_start = s.speed_end = cases[i].speed;
        s.travel = cases[i].travel;
        s.start_row = cases[i].start;
        s.rest_lines = cases[i].rest;
        s.right = cases[i].right;
        r = swipe (seed, &s);
        g_assert_cmpint (r.verdict, ==, cases[i].want);
        g_free (r.image);
      }
}

static void
test_assemble_short (void)
{
  for (guint32 seed = 1; seed <= 4; seed++)
    {
      SimSwipe s = sim_swipe_default ();
      Swiped r;

      s.seed = seed;
      s.travel = 150;
      r = swipe (seed, &s);
      /* a quarter of a finger, stitched right but too little to match */
      g_assert_cmpint (r.verdict, ==, VFS495_SWIPE_TOO_SHORT);
      g_assert_cmpint (r.info.rows, <, 185);
      g_free (r.image);
    }
}

static void
test_assemble_tiny (void)
{
  g_autofree guint8 *lines = g_malloc0 (50 * VFS495_LINE_WIDTH);
  g_autoptr(GError) error = NULL;
  Vfs495AssembleInfo info;
  guint8 *image = vfs495_assemble (lines, 50, &info, &error);

  g_assert_null (image);
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_FAILED);
  g_assert_cmpint (vfs495_swipe_verdict (NULL, &info), ==, VFS495_SWIPE_TOO_SHORT);
}

static void
test_assemble_dead_column (void)
{
  SimSwipe s = sim_swipe_default ();
  Swiped r;
  double mean = 0, var = 0;

  s.dead_column = 37;
  r = swipe (1, &s);
  g_assert_cmpint (r.verdict, ==, VFS495_SWIPE_OK);
  g_assert_cmpint (r.info.bad_columns, >=, 1);
  /* repaired from its neighbours: the column carries ridges like the rest */
  for (int y = 0; y < r.info.rows; y++)
    mean += r.image[(gsize) y * VFS495_MAIN_WIDTH + 37];
  mean /= r.info.rows;
  for (int y = 0; y < r.info.rows; y++)
    var += pow (r.image[(gsize) y * VFS495_MAIN_WIDTH + 37] - mean, 2);
  g_assert_cmpfloat (sqrt (var / r.info.rows), >, 20);
  g_free (r.image);
}

static void
test_assemble_deterministic (void)
{
  g_autoptr(SimFinger) f = sim_finger_new (7, 600);
  SimSwipe s = sim_swipe_default ();
  g_autofree guint8 *lines = NULL;
  g_autofree guint8 *a = NULL;
  g_autofree guint8 *b = NULL;
  Vfs495AssembleInfo ia, ib;
  int n;

  /* the lag search runs on all cores; its result must not depend on their timing */
  lines = sim_swipe_lines (f, &s, &n);
  a = vfs495_assemble (lines, n, &ia, NULL);
  b = vfs495_assemble (lines, n, &ib, NULL);
  g_assert_nonnull (a);
  g_assert_cmpint (ia.rows, ==, ib.rows);
  g_assert_cmpmem (a, (gsize) ia.rows * VFS495_MAIN_WIDTH, b, (gsize) ib.rows * VFS495_MAIN_WIDTH);
}

/* ---- swipe stream ------------------------------------------------------------------------ */

static const guint8 image_key[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const guint8 image_iv[16] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                     0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };

static void
test_stream_round_trip (void)
{
  g_autoptr(SimFinger) f = sim_finger_new (3, 600);
  SimSwipe s = sim_swipe_default ();
  g_autofree guint8 *lines = NULL;
  g_autofree guint8 *decoded = NULL;
  g_autoptr(GByteArray) plain = NULL;
  g_autoptr(GByteArray) stream = NULL;
  g_autoptr(GError) error = NULL;
  guint16 table[VFS495_LINE_WIDTH];
  Vfs495DecodeInfo info;
  int n, m;

  s.travel = 120;
  s.tail_lines = 10;
  lines = sim_swipe_lines (f, &s, &n);
  sim_descramble_table (table);
  plain = sim_frames (lines, n, table, NULL, 0);
  stream = sim_encrypt (plain, image_key, image_iv);
  decoded = vfs495_decode_stream (stream->data, stream->len, image_key, image_iv, table, &m, &info, &error);
  g_assert_no_error (error);
  g_assert_cmpint (m, ==, n);
  g_assert_cmpmem (decoded, (gsize) m * VFS495_LINE_WIDTH, lines, (gsize) n * VFS495_LINE_WIDTH);
  g_assert_cmpuint (info.frames, ==, n);
  g_assert_cmpuint (info.gaps, ==, 0);
  /* the status frame: its first byte is skipped, then less than a frame is left */
  g_assert_cmpuint (info.stray, ==, 1);
}

static void
test_stream_dropped_frames (void)
{
  g_autofree guint8 *lines = g_malloc0 (300 * VFS495_LINE_WIDTH);
  g_autofree guint8 *decoded = NULL;
  g_autoptr(GByteArray) plain = NULL;
  const int drop[] = { 10, 11, 200 };
  guint16 table[VFS495_LINE_WIDTH];
  Vfs495DecodeInfo info;
  int m;

  sim_descramble_table (table);
  plain = sim_frames (lines, 300, table, drop, G_N_ELEMENTS (drop));
  /* a stream cut short mid-frame, and junk between frames */
  g_byte_array_set_size (plain, plain->len - 272 - 100);
  {
    const guint8 junk[5] = { 0x01, 0x00, 0xfe, 0x01, 0x02 };
    g_byte_array_prepend (plain, junk, sizeof junk);
  }
  decoded = vfs495_frames_to_lines (plain->data, plain->len, table, &m, &info);
  g_assert_cmpint (m, ==, 300 - 3 - 1);
  g_assert_cmpuint (info.gaps, ==, 2);
  g_assert_cmpuint (info.stray, ==, 5);
}

static void
test_stream_wrong_key (void)
{
  g_autofree guint8 *lines = g_malloc0 (100 * VFS495_LINE_WIDTH);
  g_autofree guint8 *decoded = NULL;
  g_autoptr(GByteArray) plain = NULL;
  g_autoptr(GByteArray) stream = NULL;
  guint8 other[32] = { 0 };
  guint16 table[VFS495_LINE_WIDTH];
  Vfs495DecodeInfo info;
  int m;

  sim_descramble_table (table);
  plain = sim_frames (lines, 100, table, NULL, 0);
  stream = sim_encrypt (plain, image_key, image_iv);
  /* an odd length, as a stream cut off mid-block */
  decoded = vfs495_decode_stream (stream->data, stream->len - 7, other, image_iv, table, &m, &info, NULL);
  g_assert_cmpint (m, ==, 0);
  g_assert_cmpuint (info.frames, ==, 0);
}

/* ---- command file -------------------------------------------------------------------------- */

static void
put_entry (GByteArray *b, guint8 phase, guint8 flags, guint16 key, guint32 data_len, const guint8 *p, guint32 n)
{
  guint8 e[12] = { phase, flags, (guint8) key, (guint8) (key >> 8),
                   (guint8) data_len, (guint8) (data_len >> 8), (guint8) (data_len >> 16), (guint8) (data_len >> 24),
                   (guint8) n, (guint8) (n >> 8), (guint8) (n >> 16), (guint8) (n >> 24) };

  g_byte_array_append (b, e, sizeof e);
  g_byte_array_append (b, p, n);
}

/* a small command file: two commands and a descramble table (count may be wrong on purpose) */
static GByteArray *
command_file (guint32 count, const guint16 *table)
{
  GByteArray *b = g_byte_array_new ();
  const guint8 hdr[12] = { 'V', 'F', 'S', '4', '9', '5', 'C', '2', (guint8) count, 0, 0, 0 };
  const guint8 status[1] = { 0x01 }, arm[120] = { 0x02 };
  guint8 t[2 * VFS495_LINE_WIDTH];

  for (int i = 0; i < VFS495_LINE_WIDTH; i++)
    {
      t[2 * i] = (guint8) table[i];
      t[2 * i + 1] = (guint8) (table[i] >> 8);
    }
  g_byte_array_append (b, hdr, sizeof hdr);
  put_entry (b, VFS495_PHASE_PRE, 0, VFS495_NO_KEY, 4096, status, sizeof status);
  put_entry (b, VFS495_PHASE_ARM, 0, 10, 0, arm, sizeof arm);
  put_entry (b, VFS495_PHASE_DESCRAMBLE, 0, VFS495_NO_KEY, 0, t, sizeof t);
  return b;
}

static void
test_commands_parse (void)
{
  guint16 table[VFS495_LINE_WIDTH];
  g_autoptr(GByteArray) b = NULL;
  g_autoptr(GError) error = NULL;
  Vfs495Commands *cmds;
  const Vfs495Command *c;

  sim_descramble_table (table);
  b = command_file (3, table);
  cmds = vfs495_commands_parse (b->data, b->len, "test", &error);
  g_assert_no_error (error);
  g_assert_cmpuint (cmds->commands->len, ==, 2);
  c = g_ptr_array_index (cmds->commands, 0);
  g_assert_cmpint (c->phase, ==, VFS495_PHASE_PRE);
  g_assert_cmpuint (c->data_len, ==, 4096);
  g_assert_cmpuint (c->key_offset, ==, VFS495_NO_KEY);
  c = g_ptr_array_index (cmds->commands, 1);
  g_assert_cmpint (c->phase, ==, VFS495_PHASE_ARM);
  g_assert_cmpuint (c->key_offset, ==, 10);
  g_assert_cmpuint (g_bytes_get_size (c->payload), ==, 120);
  g_assert_cmpmem (cmds->descramble, sizeof table, table, sizeof table);
  vfs495_commands_free (cmds);
}

static void
expect_bad (const GByteArray *b)
{
  g_autoptr(GError) error = NULL;

  g_assert_null (vfs495_commands_parse (b->data, b->len, "test", &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
}

static void
test_commands_malformed (void)
{
  guint16 table[VFS495_LINE_WIDTH];

  sim_descramble_table (table);
  {
    g_autoptr(GByteArray) b = command_file (3, table);
    b->data[0] = 'X';                                  /* not a command file */
    expect_bad (b);
  }
  {
    g_autoptr(GByteArray) b = command_file (4, table);  /* more entries than the file has */
    expect_bad (b);
  }
  {
    g_autoptr(GByteArray) b = command_file (2, table);  /* no descramble table */
    expect_bad (b);
  }
  {
    g_autoptr(GByteArray) b = command_file (3, table);
    g_byte_array_set_size (b, b->len - 1);              /* truncated table */
    expect_bad (b);
  }
  {
    g_autoptr(GByteArray) b = command_file (3, table);
    b->data[12] = 9;                                   /* unknown phase */
    expect_bad (b);
  }
  {
    guint16 dup[VFS495_LINE_WIDTH];
    memcpy (dup, table, sizeof dup);
    dup[5] = dup[6];                                   /* not a permutation */
    g_autoptr(GByteArray) b = command_file (3, dup);
    expect_bad (b);
  }
  {
    guint16 big[VFS495_LINE_WIDTH];
    memcpy (big, table, sizeof big);
    big[0] = VFS495_LINE_WIDTH;                        /* outside the line */
    g_autoptr(GByteArray) b = command_file (3, big);
    expect_bad (b);
  }
}

/* ---- session crypto ---------------------------------------------------------------------- */

/* the sensor's side of the records: a copy of the client with the directions swapped */
static Vfs495Crypto
sensor_side (const Vfs495Crypto *host)
{
  Vfs495Crypto s = { 0 };

  s.client = host->server;
  s.server = host->client;
  return s;
}

static void
test_crypto_records (void)
{
  const guint8 premaster[48] = { 3, 0, 7 }, cr[32] = { 1 }, sr[32] = { 2 };
  const guint8 msg[] = "configuration program";
  guint8 master[48], keyblock[136];
  Vfs495Crypto host = { 0 }, sensor;

  vfs495_crypto_derive (&host, premaster, cr, sr, master, keyblock);
  sensor = sensor_side (&host);
  for (int round = 0; round < 3; round++)
    {
      g_autoptr(GByteArray) rec = vfs495_crypto_seal (&host, 0x17, msg, sizeof msg);
      g_autoptr(GByteArray) reply_rec = vfs495_crypto_seal (&sensor, 0x17, msg, round + 1);
      g_autoptr(GByteArray) got = NULL;
      g_autoptr(GByteArray) reply = NULL;
      g_autoptr(GError) error = NULL;

      g_assert_cmpuint (rec->len % 16, ==, 5 % 16);
      got = vfs495_crypto_open (&sensor, rec->data, rec->len, &error);
      g_assert_no_error (error);
      g_assert_cmpmem (got->data, got->len, msg, sizeof msg);
      reply = vfs495_crypto_open (&host, reply_rec->data, reply_rec->len, &error);
      g_assert_no_error (error);
      g_assert_cmpmem (reply->data, reply->len, msg, (gsize) round + 1);
    }
  /* a changed byte fails the MAC, and a cut record is refused */
  {
    g_autoptr(GByteArray) rec = vfs495_crypto_seal (&sensor, 0x17, msg, sizeof msg);
    g_autoptr(GError) error = NULL;
    Vfs495Crypto copy = host;

    rec->data[rec->len - 20] ^= 1;
    g_assert_null (vfs495_crypto_open (&copy, rec->data, rec->len, &error));
    g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
    g_clear_error (&error);
    copy = host;
    g_assert_null (vfs495_crypto_open (&copy, rec->data, rec->len - 1, &error));
    g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
  }
}

static EVP_PKEY *
rsa_key (guint8 modulus_le[VFS495_RSA_LEN])
{
  EVP_PKEY *pkey = EVP_RSA_gen (2048);
  BIGNUM *n = NULL;

  g_assert_nonnull (pkey);
  g_assert_true (EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_RSA_N, &n));
  g_assert_cmpint (BN_bn2lebinpad (n, modulus_le, VFS495_RSA_LEN), ==, VFS495_RSA_LEN);
  BN_free (n);
  return pkey;
}

/* a ClientHello template: command 11, length, record header, then the hello message */
static GBytes *
hello_template (void)
{
  guint8 t[3 + 5 + 4 + 2 + 32 + 4] = { 0x11, 0, 0, 0x16, 0x03, 0x00, 0, 42, 0x01, 0, 0, 38, 0x03, 0x00 };

  t[1] = sizeof t - 3;
  return g_bytes_new (t, sizeof t);
}

/*
 * The key exchange against a key made here: the sensor's private key recovers a well-formed
 * pre-master secret from the PKCS#1 block, and the host's Finished verifies under the keys both
 * sides derive from it.
 */
static void
test_crypto_handshake (void)
{
  guint8 modulus[VFS495_RSA_LEN], premaster[VFS495_RSA_LEN], master[48], keyblock[136], fin[36];
  guint8 server_hello[5 + 38] = { 0x16, 0x03, 0x00, 0, 38, 0x02, 0, 0, 34, 0x03, 0x00 };
  g_autoptr(GBytes) tpl = hello_template ();
  g_autoptr(GByteArray) hello = NULL;
  g_autoptr(GByteArray) flight = NULL;
  g_autoptr(GByteArray) hs = g_byte_array_new ();
  g_autoptr(GByteArray) finished = NULL;
  g_autoptr(GError) error = NULL;
  EVP_PKEY *pkey = rsa_key (modulus);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey (NULL, pkey, NULL);
  Vfs495Crypto host = { 0 }, sensor = { 0 };
  guint8 client_random[32], cke_be[VFS495_RSA_LEN];
  size_t pm_len = sizeof premaster;   /* OpenSSL wants room for a whole RSA block */
  const guint8 *cke;

  for (int i = 0; i < 32; i++)
    server_hello[11 + i] = (guint8) (0x40 + i);
  hello = vfs495_crypto_hello (&host, tpl, &error);
  g_assert_no_error (error);
  memcpy (client_random, hello->data + 3 + 11, 32);
  flight = vfs495_crypto_key_exchange (&host, server_hello, sizeof server_hello, modulus, &error);
  g_assert_no_error (error);

  /* 11 | len | 16 03 00 01 04 | 10 00 01 00 | RSA block | CCS | Finished record */
  g_assert_cmpuint (flight->data[0], ==, 0x11);
  g_assert_cmpuint (flight->len - 3, ==, (gsize) (flight->data[1] | flight->data[2] << 8));
  cke = flight->data + 3 + 5 + 4;
  memcpy (cke_be, cke, sizeof cke_be);
  g_assert_true (EVP_PKEY_decrypt_init (ctx) > 0);
  g_assert_true (EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_PADDING) > 0);
  g_assert_true (EVP_PKEY_decrypt (ctx, premaster, &pm_len, cke_be, sizeof cke_be) > 0);
  g_assert_cmpuint (pm_len, ==, 48);
  g_assert_cmpuint (premaster[0], ==, 0x03);
  g_assert_cmpuint (premaster[1], ==, 0x00);

  vfs495_crypto_derive (&sensor, premaster, client_random, server_hello + 11, master, keyblock);
  g_byte_array_append (hs, hello->data + 3 + 5, hello->len - 3 - 5);
  g_byte_array_append (hs, server_hello + 5, sizeof server_hello - 5);
  g_byte_array_append (hs, cke - 4, 4 + VFS495_RSA_LEN);
  vfs495_crypto_finished (master, hs->data, hs->len, fin);
  {
    Vfs495Crypto s = sensor_side (&sensor);
    const guint8 *rec = cke + VFS495_RSA_LEN + 6;

    finished = vfs495_crypto_open (&s, rec, flight->data + flight->len - rec, &error);
    g_assert_no_error (error);
    g_assert_cmpuint (finished->len, ==, 40);
    g_assert_cmpmem (finished->data + 4, 36, fin, 36);
  }
  EVP_PKEY_CTX_free (ctx);
  EVP_PKEY_free (pkey);
  vfs495_crypto_clear (&host);
}

/* deterministic mode repeats a session's random values; normal mode never does */
static void
test_crypto_deterministic (void)
{
  g_autoptr(GBytes) tpl = hello_template ();
  Vfs495Crypto c = { 0 };
  guint8 a[64], b[64];

  for (int mode = 1; mode >= 0; mode--)
    {
      g_autoptr(GByteArray) h1 = NULL;
      g_autoptr(GByteArray) h2 = NULL;

      vfs495_random_set_deterministic (mode);
      h1 = vfs495_crypto_hello (&c, tpl, NULL);
      g_assert_true (vfs495_random (a, sizeof a));
      vfs495_random_set_deterministic (mode);
      h2 = vfs495_crypto_hello (&c, tpl, NULL);
      g_assert_true (vfs495_random (b, sizeof b));
      if (mode)
        {
          g_assert_cmpmem (h1->data, h1->len, h2->data, h2->len);
          g_assert_cmpmem (a, sizeof a, b, sizeof b);
        }
      else
        {
          g_assert_true (memcmp (h1->data + 14, h2->data + 14, 32) != 0);
          g_assert_true (memcmp (a, b, sizeof a) != 0);
        }
    }
  vfs495_crypto_clear (&c);
}

/* ---- signed patches ---------------------------------------------------------------------- */

static void
test_patch_for_sensor (void)
{
  const guint8 label[8] = { 0x00, 0x40, 0x00, 0x00, 0x02, 'P', 'S', 0xff };
  guint8 payload[8 + 5 + 256 + 20], flash[4096];
  g_autofree guint8 *rsa = NULL;
  g_autofree guint8 *cached = NULL;
  g_autoptr(GError) error = NULL;
  gsize len;

  memcpy (payload, label, 8);
  payload[8] = 0x06;
  payload[9] = 0x02;
  payload[10] = 0x00;
  payload[11] = 0x00;
  payload[12] = 0x01;
  memset (payload + 13, 0x5a, 256);                    /* RSA signature */
  memset (payload + 13 + 256, 0xb0, 20);               /* body */

  /* no cache entry: the patch as HP ships it */
  memset (flash, 0xff, sizeof flash);
  rsa = vfs495_patch_for_sensor (payload, sizeof payload, flash, sizeof flash, &len, &error);
  g_assert_no_error (error);
  g_assert_cmpmem (rsa, len, payload + 8, sizeof payload - 8);

  /* with the entry: 06 02 00 20 00, the cached HMAC, the body */
  memcpy (flash + 3000, label, 8);
  memset (flash + 3008, 0xcc, 32);
  cached = vfs495_patch_for_sensor (payload, sizeof payload, flash, sizeof flash, &len, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (len, ==, 5 + 32 + 20);
  g_assert_cmpmem (cached, 5, ((const guint8[]) { 0x06, 0x02, 0x00, 0x20, 0x00 }), 5);
  g_assert_cmpuint (cached[5], ==, 0xcc);
  g_assert_cmpuint (cached[5 + 31], ==, 0xcc);
  g_assert_cmpuint (cached[5 + 32], ==, 0xb0);

  /* not a signed patch */
  payload[8] = 0x07;
  g_assert_null (vfs495_patch_for_sensor (payload, sizeof payload, flash, sizeof flash, &len, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
}

/* ---- beta diagnostics -------------------------------------------------------------------- */

static char *
diag_dir_with_until (gint64 until)
{
  g_autofree char *dir = g_dir_make_tmp ("vfs495-diag-XXXXXX", NULL);
  g_autofree char *path = g_build_filename (dir, "until", NULL);
  g_autofree char *text = g_strdup_printf ("%" G_GINT64_FORMAT "\n", until);

  g_assert_true (g_file_set_contents (path, text, -1, NULL));
  g_setenv ("VFS495_DIAG_DIR", dir, TRUE);
  return g_steal_pointer (&dir);
}

static void
remove_tree (const char *path)
{
  g_autoptr(GDir) d = g_dir_open (path, 0, NULL);
  const char *name;

  while (d && (name = g_dir_read_name (d)))
    {
      g_autofree char *p = g_build_filename (path, name, NULL);

      if (g_file_test (p, G_FILE_TEST_IS_DIR))
        remove_tree (p);
      else
        g_unlink (p);
    }
  g_rmdir (path);
}

static guint
count_swipes (const char *dir)
{
  g_autoptr(GDir) d = g_dir_open (dir, 0, NULL);
  const char *name;
  guint n = 0;

  while ((name = g_dir_read_name (d)))
    n += g_ascii_isdigit (name[0]);
  return n;
}

static void
test_diag_switch (void)
{
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  g_autofree char *past = diag_dir_with_until (now - 1);
  g_autofree char *future = NULL;
  Vfs495Diag *d;

  g_assert_null (vfs495_diag_open ());                 /* expired */
  remove_tree (past);
  g_assert_null (vfs495_diag_open ());                 /* no folder: off */
  future = diag_dir_with_until (now + 3600);
  d = vfs495_diag_open ();
  g_assert_nonnull (d);
  vfs495_diag_unref (d);
  remove_tree (future);
  g_unsetenv ("VFS495_DIAG_DIR");
}

static void
test_diag_records (void)
{
  g_autofree char *dir = diag_dir_with_until (g_get_real_time () / G_USEC_PER_SEC + 3600);
  g_autoptr(Vfs495Diag) d = vfs495_diag_open ();
  g_autoptr(GDir) list = NULL;
  g_autofree char *swipe_dir = NULL;
  g_autofree char *json = NULL;
  g_autofree char *events = NULL;
  g_autofree char *pgm = NULL;
  g_autofree char *path = NULL;
  const guint8 image[VFS495_MAIN_WIDTH * 2] = { 7 }, plain[272] = { 1, 0xfe };
  Vfs495DiagSwipe w = { .action = "verify", .verdict = "ok", .error = "a \"quoted\" message", .lines = 2 };
  const char *name;
  gsize len;
  GStatBuf st;

  g_assert_nonnull (d);
  vfs495_diag_event (d, "armed: %s", "waiting");
  w.info.rows = 2;
  vfs495_diag_swipe (d, &w, plain, sizeof plain, image, 2);

  path = g_build_filename (dir, "events.log", NULL);
  g_assert_true (g_file_get_contents (path, &events, NULL, NULL));
  g_assert_nonnull (strstr (events, "ms  armed: waiting\n"));
  g_assert_cmpint (g_stat (path, &st), ==, 0);
  g_assert_cmpint (st.st_mode & 0777, ==, 0600);

  list = g_dir_open (dir, 0, NULL);
  while ((name = g_dir_read_name (list)))
    if (g_ascii_isdigit (name[0]))
      swipe_dir = g_build_filename (dir, name, NULL);
  g_assert_nonnull (swipe_dir);
  g_assert_true (g_str_has_suffix (swipe_dir, "-verify"));
  g_assert_cmpint (g_stat (swipe_dir, &st), ==, 0);
  g_assert_cmpint (st.st_mode & 0777, ==, 0700);
  g_clear_pointer (&path, g_free);
  path = g_build_filename (swipe_dir, "swipe.json", NULL);
  g_assert_true (g_file_get_contents (path, &json, NULL, NULL));
  g_assert_nonnull (strstr (json, "\"verdict\": \"ok\""));
  g_assert_nonnull (strstr (json, "\"error\": \"a \\\"quoted\\\" message\""));
  g_assert_nonnull (strstr (json, "\"rows\": 2"));
  g_clear_pointer (&path, g_free);
  path = g_build_filename (swipe_dir, "image.pgm", NULL);
  g_assert_true (g_file_get_contents (path, &pgm, &len, NULL));
  g_assert_true (g_str_has_prefix (pgm, "P5\n200 2\n255\n"));
  g_assert_cmpuint (len, ==, strlen ("P5\n200 2\n255\n") + sizeof image);
  g_assert_cmpint (g_stat (path, &st), ==, 0);
  g_assert_cmpint (st.st_mode & 0777, ==, 0600);

  remove_tree (dir);
  g_unsetenv ("VFS495_DIAG_DIR");
}

static void
test_diag_prune (void)
{
  g_autofree char *dir = diag_dir_with_until (g_get_real_time () / G_USEC_PER_SEC + 3600);
  g_autoptr(Vfs495Diag) d = vfs495_diag_open ();
  Vfs495DiagSwipe w = { .action = "verify", .verdict = "ok" };

  for (int i = 0; i < VFS495_DIAG_MAX_SWIPES + 5; i++)
    vfs495_diag_swipe (d, &w, NULL, 0, NULL, 0);
  g_assert_cmpuint (count_swipes (dir), ==, VFS495_DIAG_MAX_SWIPES);
  remove_tree (dir);
  g_unsetenv ("VFS495_DIAG_DIR");
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/assemble/normal", test_assemble_normal);
  g_test_add_func ("/assemble/speed-change", test_assemble_speed_change);
  g_test_add_func ("/assemble/verdicts", test_assemble_verdicts);
  g_test_add_func ("/assemble/short", test_assemble_short);
  g_test_add_func ("/assemble/tiny", test_assemble_tiny);
  g_test_add_func ("/assemble/dead-column", test_assemble_dead_column);
  g_test_add_func ("/assemble/deterministic", test_assemble_deterministic);
  g_test_add_func ("/stream/round-trip", test_stream_round_trip);
  g_test_add_func ("/stream/dropped-frames", test_stream_dropped_frames);
  g_test_add_func ("/stream/wrong-key", test_stream_wrong_key);
  g_test_add_func ("/commands/parse", test_commands_parse);
  g_test_add_func ("/commands/malformed", test_commands_malformed);
  g_test_add_func ("/crypto/records", test_crypto_records);
  g_test_add_func ("/crypto/handshake", test_crypto_handshake);
  g_test_add_func ("/crypto/deterministic", test_crypto_deterministic);
  g_test_add_func ("/patch/for-sensor", test_patch_for_sensor);
  g_test_add_func ("/diag/switch", test_diag_switch);
  g_test_add_func ("/diag/records", test_diag_records);
  g_test_add_func ("/diag/prune", test_diag_prune);
  return g_test_run ();
}
