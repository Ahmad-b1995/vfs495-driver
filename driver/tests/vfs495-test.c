/*
 * Regression tests for the VFS495 driver code, run by `meson test`.
 *
 *   vfs495-test GOLDEN CAPTURES           run all tests
 *   vfs495-test --update GOLDEN CAPTURES  recompute the expected results in GOLDEN
 *
 * The test data is private (recordings of HP's tool, fingerprint scans) and lives in the
 * git-ignored captures/ folder; GOLDEN only holds verdicts, sizes and hashes. Tests whose data
 * is missing are skipped, and without any data the run reports a skip (exit 77).
 *
 *   commands  captures/vfs495-commands.bin has the structure the driver relies on
 *   crypto    captures/test-vectors/NAME.vec (driver/tests/make-vectors.py): key derivation,
 *             Finished, and every record of a recorded HP session, byte for byte
 *   decode    captures/test-vectors/NAME.stream + .key: a swipe HP's tool received
 *   swipe     a saved scan (PATH.lines.raw): stitcher verdict, size and image
 */
#include <gio/gio.h>
#include <stdio.h>
#include <string.h>

#include "vfs495-assemble.h"
#include "vfs495-commands.h"
#include "vfs495-image.h"
#include "vfs495-protocol.h"

static guint passed, failed, skipped;

static void
result (gboolean ok, const char *name, const char *detail)
{
  if (ok)
    passed++;
  else
    failed++;
  g_print ("%s %s%s%s\n", ok ? "ok  " : "FAIL", name, detail ? ": " : "", detail ? detail : "");
}

static void
skip (const char *name, const char *why)
{
  skipped++;
  g_print ("skip %s: %s\n", name, why);
}

static GBytes *
unhex (const char *hex)
{
  gsize n = strlen (hex) / 2;
  guint8 *out = g_malloc (MAX (n, 1));

  for (gsize i = 0; i < n; i++)
    out[i] = (guint8) (g_ascii_xdigit_value (hex[2 * i]) << 4 | g_ascii_xdigit_value (hex[2 * i + 1]));
  return g_bytes_new_take (out, n);
}

static gboolean
bytes_equal (GBytes *b, const guint8 *data, gsize len)
{
  gsize n;
  const guint8 *p = g_bytes_get_data (b, &n);

  return n == len && memcmp (p, data, len) == 0;
}

static char *
sha16 (const guint8 *data, gsize len)
{
  g_autofree char *full = g_compute_checksum_for_data (G_CHECKSUM_SHA256, data, len);

  return g_strndup (full, 16);
}

/* ---- command file ------------------------------------------------------------------------- */

static Vfs495Commands *
test_commands (const char *captures)
{
  g_autofree char *path = g_build_filename (captures, "vfs495-commands.bin", NULL);
  g_autoptr(GError) error = NULL;
  Vfs495Commands *cmds = vfs495_commands_load (path, &error);
  guint count[VFS495_PHASE_CLOSE + 1] = { 0 };
  gboolean flash = FALSE, key = FALSE, perm = TRUE;
  gboolean seen[VFS495_LINE_WIDTH] = { FALSE };

  if (!cmds)
    {
      if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        skip ("commands", "no command file");
      else
        result (FALSE, "commands", error->message);
      return NULL;
    }
  for (guint i = 0; i < cmds->commands->len; i++)
    {
      const Vfs495Command *c = g_ptr_array_index (cmds->commands, i);

      count[c->phase]++;
      flash |= c->phase == VFS495_PHASE_PRE && c->data_len == VFS495_FLASH_BLOCK_LEN;
      key |= c->phase == VFS495_PHASE_ARM && c->key_offset != VFS495_NO_KEY;
    }
  for (int k = 0; k < VFS495_LINE_WIDTH; k++)
    {
      guint16 v = cmds->descramble[k];
      perm &= v < VFS495_LINE_WIDTH && !seen[v];
      if (v < VFS495_LINE_WIDTH)
        seen[v] = TRUE;
    }
  {
    g_autofree char *detail = g_strdup_printf ("%u pre-session, %u setup, %u re-arm, %u close", count[VFS495_PHASE_PRE],
                                               count[VFS495_PHASE_SETUP], count[VFS495_PHASE_REARM],
                                               count[VFS495_PHASE_CLOSE]);
    result (count[VFS495_PHASE_HELLO] == 1 && count[VFS495_PHASE_ARM] == 1 && count[VFS495_PHASE_SETUP] > 0 &&
            count[VFS495_PHASE_CLOSE] > 0 && flash && key && perm, "commands", detail);
  }
  return cmds;
}

/* ---- crypto against a recorded session ----------------------------------------------------- */

static void
test_crypto (const char *path)
{
  g_autofree char *name = g_path_get_basename (path);
  g_autofree char *text = NULL;
  g_auto(GStrv) lines = NULL;
  g_autoptr(GHashTable) fields = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_bytes_unref);
  Vfs495Crypto c = { 0 };
  guint8 master[48], keyblock[136], fin[36];
  guint n_out = 0, n_in = 0, bad_out = 0, bad_in = 0;
  gboolean derive_ok, fin_ok, first_in = TRUE;
  GBytes *b;

  if (!g_file_get_contents (path, &text, NULL, NULL))
    {
      skip (name, "unreadable");
      return;
    }
  lines = g_strsplit (text, "\n", -1);
  for (int i = 0; lines[i]; i++)
    {
      g_auto(GStrv) w = g_strsplit (lines[i], " ", 2);
      if (w[0] && w[1] && strcmp (w[0], "out") != 0 && strcmp (w[0], "in") != 0)
        g_hash_table_insert (fields, g_strdup (w[0]), unhex (w[1]));
    }
  for (const char *const *f = (const char *const[]) { "premaster", "client_random", "server_random", "master",
                                                       "keyblock", "handshake", "finished", NULL }; *f; f++)
    if (!g_hash_table_contains (fields, *f))
      {
        result (FALSE, name, "vector file lacks a field");
        return;
      }

  vfs495_crypto_derive (&c, g_bytes_get_data (g_hash_table_lookup (fields, "premaster"), NULL),
                        g_bytes_get_data (g_hash_table_lookup (fields, "client_random"), NULL),
                        g_bytes_get_data (g_hash_table_lookup (fields, "server_random"), NULL), master, keyblock);
  derive_ok = bytes_equal (g_hash_table_lookup (fields, "master"), master, 48) &&
              bytes_equal (g_hash_table_lookup (fields, "keyblock"), keyblock, 136);
  b = g_hash_table_lookup (fields, "handshake");
  vfs495_crypto_finished (master, g_bytes_get_data (b, NULL), g_bytes_get_size (b), fin);
  fin_ok = bytes_equal (g_hash_table_lookup (fields, "finished"), fin, 36);

  /* every client record re-encrypted must equal what HP sent; every server transfer must
   * decrypt with valid MACs, in order (CBC state and sequence numbers carry over) */
  for (int i = 0; lines[i]; i++)
    {
      g_auto(GStrv) w = g_strsplit (lines[i], " ", 4);

      if (g_strcmp0 (w[0], "out") == 0 && w[1] && w[2] && w[3])
        {
          g_autoptr(GBytes) plain = unhex (w[2]);
          g_autoptr(GBytes) wire = unhex (w[3]);
          g_autoptr(GByteArray) sealed = vfs495_crypto_seal (&c, (guint8) g_ascii_strtoull (w[1], NULL, 16),
                                                             g_bytes_get_data (plain, NULL), g_bytes_get_size (plain));
          n_out++;
          bad_out += !bytes_equal (wire, sealed->data, sealed->len);
        }
      else if (g_strcmp0 (w[0], "in") == 0 && w[1])
        {
          g_autoptr(GBytes) data = unhex (w[1]);
          g_autoptr(GError) error = NULL;
          gsize len;
          const guint8 *p = g_bytes_get_data (data, &len);

          n_in++;
          if (first_in)
            {
              bad_in += !vfs495_crypto_finish (&c, p, len, &error);
              first_in = FALSE;
            }
          else
            {
              g_autoptr(GByteArray) opened = vfs495_crypto_open (&c, p, len, &error);
              bad_in += opened == NULL;
            }
        }
    }
  vfs495_crypto_clear (&c);
  {
    g_autofree char *detail = g_strdup_printf ("keys %s, Finished %s, %u/%u client records identical, "
                                               "%u/%u server transfers verified",
                                               derive_ok ? "ok" : "WRONG", fin_ok ? "ok" : "WRONG",
                                               n_out - bad_out, n_out, n_in - bad_in, n_in);
    result (derive_ok && fin_ok && n_out > 0 && n_in > 0 && !bad_out && !bad_in, name, detail);
  }
}

/* ---- golden results ------------------------------------------------------------------------ */

/* decode: "decode NAME FRAMES GAPS SHA" */
static char *
run_decode (const char *captures, const char *vname, const Vfs495Commands *cmds, GError **error)
{
  g_autofree char *spath = g_strdup_printf ("%s/test-vectors/%s.stream", captures, vname);
  g_autofree char *kpath = g_strdup_printf ("%s/test-vectors/%s.key", captures, vname);
  g_autofree char *stream = NULL;
  g_autofree char *key = NULL;
  g_autofree guint8 *lines = NULL;
  g_autofree char *hash = NULL;
  gsize slen, klen;
  Vfs495DecodeInfo info;
  int n;

  if (!cmds)
    {
      g_set_error_literal (error, G_FILE_ERROR, G_FILE_ERROR_NOENT, "no command file");
      return NULL;
    }
  if (!g_file_get_contents (spath, &stream, &slen, error) || !g_file_get_contents (kpath, &key, &klen, error))
    return NULL;
  lines = vfs495_decode_stream ((guint8 *) stream, slen, (guint8 *) key, (guint8 *) key + 32, cmds->descramble, &n,
                                &info, error);
  if (!lines)
    return NULL;
  hash = sha16 (lines, (gsize) n * VFS495_LINE_WIDTH);
  return g_strdup_printf ("%u %u %s", info.frames, info.gaps, hash);
}

/* swipe: "swipe PATH VERDICT ROWS SHA" (verdict with spaces as dashes) */
static char *
run_swipe (const char *captures, const char *rel, GError **error)
{
  g_autofree char *path = g_build_filename (captures, rel, NULL);
  g_autofree char *data = NULL;
  g_autoptr(GByteArray) lines = g_byte_array_new ();
  g_autoptr(GError) local = NULL;
  g_autofree guint8 *img = NULL;
  g_autofree char *verdict = NULL;
  g_autofree char *hash = NULL;
  Vfs495AssembleInfo info;
  gsize len, pos = 0;

  if (!g_file_get_contents (path, &data, &len, error))
    return NULL;
  while (pos + 2 <= len)
    {
      guint n = (guint8) data[pos] | (guint8) data[pos + 1] << 8;
      pos += 2;
      if (n != VFS495_LINE_WIDTH || pos + n > len)
        break;
      g_byte_array_append (lines, (guint8 *) data + pos, n);
      pos += n;
    }
  img = vfs495_assemble (lines->data, lines->len / VFS495_LINE_WIDTH, &info, &local);
  verdict = g_strdelimit (g_strdup (vfs495_swipe_verdict_name (vfs495_swipe_verdict (img, &info))), " ", '-');
  hash = img ? sha16 (img, (gsize) info.rows * VFS495_MAIN_WIDTH) : g_strdup ("-");
  return g_strdup_printf ("%s %d %s", verdict, img ? info.rows : 0, hash);
}

static int
run_golden (const char *golden, const char *captures, const Vfs495Commands *cmds, gboolean update)
{
  g_autofree char *text = NULL;
  g_auto(GStrv) lines = NULL;
  GString *out = g_string_new (NULL);
  g_autoptr(GError) error = NULL;

  if (!g_file_get_contents (golden, &text, NULL, &error))
    {
      result (FALSE, "golden", error->message);
      g_string_free (out, TRUE);
      return 1;
    }
  lines = g_strsplit (text, "\n", -1);
  for (int i = 0; lines[i]; i++)
    {
      g_auto(GStrv) w = g_strsplit (lines[i], " ", 3);
      g_autoptr(GError) local = NULL;
      g_autofree char *got = NULL;
      g_autofree char *name = NULL;

      if (!w[0] || !w[1] || lines[i][0] == '#' || (strcmp (w[0], "decode") != 0 && strcmp (w[0], "swipe") != 0))
        {
          if (lines[i][0] || lines[i + 1])
            g_string_append_printf (out, "%s\n", lines[i]);
          continue;
        }
      name = g_strdup_printf ("%s %s", w[0], w[1]);
      got = strcmp (w[0], "decode") == 0 ? run_decode (captures, w[1], cmds, &local) : run_swipe (captures, w[1], &local);
      if (!got)
        {
          skip (name, local->message);
          g_string_append_printf (out, "%s\n", lines[i]);
          continue;
        }
      if (update)
        {
          if (g_strcmp0 (w[2], got) != 0)
            g_print ("updated %s: %s -> %s\n", name, w[2] ? w[2] : "(new)", got);
          g_string_append_printf (out, "%s %s %s\n", w[0], w[1], got);
        }
      else
        {
          g_autofree char *detail = g_strcmp0 (w[2], got) == 0 ? g_strdup (got) :
                                    g_strdup_printf ("expected %s, got %s", w[2] ? w[2] : "?", got);
          result (g_strcmp0 (w[2], got) == 0, name, detail);
        }
    }
  if (update && !g_file_set_contents (golden, out->str, out->len, &error))
    {
      g_printerr ("%s\n", error->message);
      g_string_free (out, TRUE);
      return 1;
    }
  g_string_free (out, TRUE);
  return 0;
}

int
main (int argc, char **argv)
{
  gboolean update = argc > 1 && strcmp (argv[1], "--update") == 0;
  const char *golden = argv[update ? 2 : 1];
  const char *captures = argv[update ? 3 : 2];
  g_autoptr(GDir) vdir = NULL;
  g_autofree char *vpath = NULL;
  Vfs495Commands *cmds;
  const char *entry;

  if (argc != (update ? 4 : 3))
    {
      g_printerr ("usage: vfs495-test [--update] GOLDEN CAPTURES\n");
      return 2;
    }
  if (!g_file_test (captures, G_FILE_TEST_IS_DIR))
    {
      g_print ("no test data in %s: skipped\n", captures);
      return 77;
    }

  cmds = test_commands (captures);
  if (!update)
    {
      vpath = g_build_filename (captures, "test-vectors", NULL);
      vdir = g_dir_open (vpath, 0, NULL);
      while (vdir && (entry = g_dir_read_name (vdir)))
        if (g_str_has_suffix (entry, ".vec"))
          {
            g_autofree char *p = g_build_filename (vpath, entry, NULL);
            test_crypto (p);
          }
      if (!vdir)
        skip ("crypto", "no test vectors (driver/tests/make-vectors.py)");
    }
  if (run_golden (golden, captures, cmds, update) != 0)
    failed++;
  vfs495_commands_free (cmds);

  g_print ("\n%u passed, %u failed, %u skipped\n", passed, failed, skipped);
  if (failed)
    return 1;
  return passed ? 0 : 77;
}
