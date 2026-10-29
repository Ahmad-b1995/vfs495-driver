#include "vfs495-diag.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct _Vfs495Diag
{
  gint    ref;
  char   *dir;
  gint64  opened;    /* monotonic, for the event times */
  GMutex  lock;      /* events and pruning */
};

Vfs495Diag *
vfs495_diag_open (void)
{
  const char *dir = g_getenv ("VFS495_DIAG_DIR");
  g_autofree char *until_path = NULL;
  g_autofree char *until = NULL;
  Vfs495Diag *diag;
  gint64 end;

  dir = dir ? dir : VFS495_DIAG_DIR;
  until_path = g_build_filename (dir, "until", NULL);
  if (!g_file_get_contents (until_path, &until, NULL, NULL))
    return NULL;
  end = g_ascii_strtoll (until, NULL, 10);
  if (end <= g_get_real_time () / G_USEC_PER_SEC)
    return NULL;
  diag = g_new0 (Vfs495Diag, 1);
  diag->ref = 1;
  diag->dir = g_strdup (dir);
  diag->opened = g_get_monotonic_time ();
  g_mutex_init (&diag->lock);
  return diag;
}

Vfs495Diag *
vfs495_diag_ref (Vfs495Diag *diag)
{
  if (diag)
    g_atomic_int_inc (&diag->ref);
  return diag;
}

void
vfs495_diag_unref (Vfs495Diag *diag)
{
  if (!diag || !g_atomic_int_dec_and_test (&diag->ref))
    return;
  g_mutex_clear (&diag->lock);
  g_free (diag->dir);
  g_free (diag);
}

static char *
wall_clock (void)
{
  g_autoptr(GDateTime) now = g_date_time_new_now_local ();

  return g_date_time_format (now, "%Y-%m-%d %H:%M:%S.%f%z");
}

void
vfs495_diag_event (Vfs495Diag *diag, const char *format, ...)
{
  g_autofree char *path = NULL;
  g_autofree char *text = NULL;
  g_autofree char *when = NULL;
  va_list args;
  GStatBuf st;
  FILE *f;
  int fd;

  if (!diag)
    return;
  va_start (args, format);
  text = g_strdup_vprintf (format, args);
  va_end (args);
  when = wall_clock ();
  path = g_build_filename (diag->dir, "events.log", NULL);

  g_mutex_lock (&diag->lock);
  if (g_stat (path, &st) == 0 && st.st_size > VFS495_DIAG_MAX_EVENTS)
    {
      g_autofree char *old = g_strconcat (path, ".1", NULL);
      g_rename (path, old);
    }
  fd = g_open (path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (fd >= 0 && (f = fdopen (fd, "a")))
    {
      fprintf (f, "%s %+9.1f ms  %s\n", when, (g_get_monotonic_time () - diag->opened) / 1000.0, text);
      fclose (f);
    }
  else if (fd >= 0)
    {
      close (fd);
    }
  g_mutex_unlock (&diag->lock);
}

static void
json_string (GString *s, const char *key, const char *value)
{
  g_string_append_printf (s, "  \"%s\": ", key);
  if (!value)
    {
      g_string_append (s, "null,\n");
      return;
    }
  g_string_append_c (s, '"');
  for (const char *p = value; *p; p++)
    {
      if (*p == '"' || *p == '\\')
        g_string_append_printf (s, "\\%c", *p);
      else if ((guchar) *p < 0x20)
        g_string_append_printf (s, "\\u%04x", (guchar) *p);
      else
        g_string_append_c (s, *p);
    }
  g_string_append (s, "\",\n");
}

static void
write_file (const char *dir, const char *name, const void *data, gsize len)
{
  g_autofree char *path = g_build_filename (dir, name, NULL);
  g_autoptr(GError) error = NULL;

  if (!g_file_set_contents_full (path, data, (gssize) len, G_FILE_SET_CONTENTS_NONE, 0600, &error))
    g_warning ("diagnostics: %s", error->message);
}

static gint
compare_names (gconstpointer a, gconstpointer b)
{
  return strcmp (*(char *const *) a, *(char *const *) b);
}

/* swipe folders are named by time, so sorted names are oldest first */
static void
prune (Vfs495Diag *diag)
{
  g_autoptr(GDir) d = g_dir_open (diag->dir, 0, NULL);
  g_autoptr(GPtrArray) swipes = g_ptr_array_new_with_free_func (g_free);
  const char *name;

  if (!d)
    return;
  while ((name = g_dir_read_name (d)))
    if (g_ascii_isdigit (name[0]))
      g_ptr_array_add (swipes, g_strdup (name));
  if (swipes->len <= VFS495_DIAG_MAX_SWIPES)
    return;
  g_ptr_array_sort (swipes, compare_names);
  for (guint i = 0; i < swipes->len - VFS495_DIAG_MAX_SWIPES; i++)
    {
      g_autofree char *path = g_build_filename (diag->dir, g_ptr_array_index (swipes, i), NULL);
      g_autoptr(GDir) sd = g_dir_open (path, 0, NULL);
      const char *f;

      while (sd && (f = g_dir_read_name (sd)))
        {
          g_autofree char *fp = g_build_filename (path, f, NULL);
          g_unlink (fp);
        }
      g_rmdir (path);
    }
}

void
vfs495_diag_swipe (Vfs495Diag *diag, const Vfs495DiagSwipe *w, const guint8 *plain, gsize plain_len,
                   const guint8 *image, int rows)
{
  g_autoptr(GDateTime) now = NULL;
  g_autoptr(GString) json = NULL;
  g_autofree char *stamp = NULL;
  g_autofree char *name = NULL;
  g_autofree char *dir = NULL;
  g_autofree char *when = NULL;
  const Vfs495AssembleInfo *i = &w->info;

  if (!diag)
    return;
  now = g_date_time_new_now_local ();
  stamp = g_date_time_format (now, "%Y%m%d-%H%M%S");
  name = g_strdup_printf ("%s.%03d-%s", stamp, g_date_time_get_microsecond (now) / 1000,
                          w->action ? w->action : "unknown");
  dir = g_build_filename (diag->dir, name, NULL);
  for (int k = 2; g_mkdir (dir, 0700) != 0; k++)
    {
      if (errno != EEXIST || k > 99)
        {
          g_warning ("diagnostics: cannot create %s: %s", dir, g_strerror (errno));
          return;
        }
      g_free (dir);
      dir = g_strdup_printf ("%s/%s.%d", diag->dir, name, k);
    }

  when = g_date_time_format_iso8601 (now);
  json = g_string_new ("{\n");
  json_string (json, "time", when);
  json_string (json, "driver", VFS495_VERSION);
  json_string (json, "action", w->action);
  json_string (json, "verdict", w->verdict);
  json_string (json, "error", w->error);
  g_string_append_printf (json,
                          "  \"lines\": %d,\n  \"frames\": %u,\n  \"sequence_gaps\": %u,\n  \"stray_bytes\": %u,\n"
                          "  \"stream_bytes\": %u,\n  \"after_abort\": %u,\n  \"abort_status\": \"%04x\",\n"
                          "  \"port_reset\": %s,\n  \"recovering\": %s,\n",
                          w->lines, w->decoded.frames, w->decoded.gaps, w->decoded.stray, w->stream_bytes,
                          w->after_abort, w->abort_status, w->port_reset ? "true" : "false",
                          w->recovering ? "true" : "false");
  g_string_append_printf (json,
                          "  \"ms\": {\"setup\": %.1f, \"wait\": %.1f, \"swipe\": %.1f, \"decode\": %.1f, "
                          "\"assemble\": %.1f},\n",
                          w->setup_ms, w->wait_ms, w->swipe_ms, w->decode_ms, w->assemble_ms);
  g_string_append_printf (json,
                          "  \"assembly\": {\"first_line\": %d, \"last_line\": %d, \"rows\": %d, \"bad_columns\": %d, "
                          "\"region_lines\": %d, \"trusted\": %d, \"confident\": %.4f, \"fast\": %.4f, "
                          "\"still\": %.4f, \"median_lag\": %.1f, \"coverage\": %.4f}\n}\n",
                          i->first_line, i->last_line, i->rows, i->bad_columns, i->region_lines, i->trusted,
                          i->confident, i->fast, i->still_fraction, i->median_lag, i->coverage);
  write_file (dir, "swipe.json", json->str, json->len);
  if (plain)
    write_file (dir, "stream.dec", plain, plain_len);
  if (image && rows > 0)
    {
      g_autofree char *hdr = g_strdup_printf ("P5\n%d %d\n255\n", VFS495_MAIN_WIDTH, rows);
      gsize hlen = strlen (hdr), ilen = (gsize) VFS495_MAIN_WIDTH * rows;
      g_autofree guint8 *pgm = g_malloc (hlen + ilen);

      memcpy (pgm, hdr, hlen);
      memcpy (pgm + hlen, image, ilen);
      write_file (dir, "image.pgm", pgm, hlen + ilen);
    }

  g_mutex_lock (&diag->lock);
  prune (diag);
  g_mutex_unlock (&diag->lock);
}
