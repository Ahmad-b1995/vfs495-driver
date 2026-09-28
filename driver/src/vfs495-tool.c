/*
 * vfs495-tool: exercise the driver's building blocks outside libfprint.
 *
 *   vfs495-tool assemble LINES.raw OUT.pgm
 *       stitch descrambled scan lines (upstream format: repeated [u16 len][264 bytes])
 *   vfs495-tool capture COMMANDS.bin OUT_PREFIX [COUNT [TIMEOUT_S]]
 *       run the sensor session, capture COUNT swipes (waiting up to TIMEOUT_S each), write
 *       OUT_PREFIX.N.pgm and .lines.raw
 */
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs495-assemble.h"
#include "vfs495-image.h"
#include "vfs495-proto.h"

static int swipe_timeout_s = 30;

static gboolean
write_pgm (const char *path, const guint8 *img, int w, int h, GError **error)
{
  g_autofree char *header = g_strdup_printf ("P5\n%d %d\n255\n", w, h);
  g_autoptr(GByteArray) out = g_byte_array_new ();

  g_byte_array_append (out, (const guint8 *) header, strlen (header));
  g_byte_array_append (out, img, (guint) w * h);
  return g_file_set_contents (path, (const char *) out->data, out->len, error);
}

static guint8 *
read_lines_raw (const char *path, int *n_lines, GError **error)
{
  g_autofree char *data = NULL;
  gsize len, pos = 0;
  GByteArray *lines = g_byte_array_new ();

  if (!g_file_get_contents (path, &data, &len, error))
    return NULL;
  while (pos + 2 <= len)
    {
      guint n = (guint8) data[pos] | (guint8) data[pos + 1] << 8;
      pos += 2;
      if (n != VFS495_LINE_WIDTH || pos + n > len)
        break;
      g_byte_array_append (lines, (const guint8 *) data + pos, n);
      pos += n;
    }
  *n_lines = lines->len / VFS495_LINE_WIDTH;
  return g_byte_array_free (lines, FALSE);
}

static int
cmd_assemble (int argc, char **argv)
{
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *lines = NULL;
  g_autofree guint8 *img = NULL;
  Vfs495AssembleInfo info;
  gint64 t0;
  int n;

  if (argc != 4)
    {
      g_printerr ("usage: vfs495-tool assemble LINES.raw OUT.pgm\n");
      return 2;
    }
  lines = read_lines_raw (argv[2], &n, &error);
  if (!lines)
    {
      g_printerr ("%s\n", error->message);
      return 1;
    }
  t0 = g_get_monotonic_time ();
  img = vfs495_assemble (lines, n, &info, &error);
  g_print ("%s: region %d lines, trusted %d, confident %.0f%%, fast %.0f%%, median lag %.0f, still %.0f%%, "
           "coverage %.0f%% -> %s\n", argv[2], info.region_lines, info.trusted, 100 * info.confident,
           100 * info.fast, info.median_lag, 100 * info.still_fraction, 100 * info.coverage,
           vfs495_swipe_verdict_name (vfs495_swipe_verdict (img, &info)));
  if (!img)
    {
      g_printerr ("%s: %s\n", argv[2], error->message);
      return 1;
    }
  if (!write_pgm (argv[3], img, VFS495_MAIN_WIDTH, info.rows, &error))
    {
      g_printerr ("%s\n", error->message);
      return 1;
    }
  g_print ("%s: %d lines, print lines %d-%d, %d rows, %d bad columns, still %.0f%%, %.2f s\n",
           argv[2], n, info.first_line, info.last_line, info.rows, info.bad_columns,
           100 * info.still_fraction, (g_get_monotonic_time () - t0) / 1e6);
  return 0;
}

static gpointer
cancel_after (gpointer data)
{
  GCancellable *c = data;

  for (int i = 0; i < swipe_timeout_s * 10 && !g_cancellable_is_cancelled (c); i++)
    g_usleep (100000);
  g_cancellable_cancel (c);
  return NULL;
}

static gboolean
write_lines_raw (const char *path, const guint8 *lines, int n, GError **error)
{
  g_autoptr(GByteArray) out = g_byte_array_new ();
  const guint8 len[2] = { VFS495_LINE_WIDTH & 0xff, VFS495_LINE_WIDTH >> 8 };

  for (int r = 0; r < n; r++)
    {
      g_byte_array_append (out, len, 2);
      g_byte_array_append (out, lines + (gsize) r * VFS495_LINE_WIDTH, VFS495_LINE_WIDTH);
    }
  return g_file_set_contents (path, (const char *) out->data, out->len, error);
}

static int
cmd_capture (int argc, char **argv)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GUsbContext) ctx = NULL;
  g_autoptr(GUsbDevice) usb = NULL;
  Vfs495Commands *cmds = NULL;
  Vfs495Session *s = NULL;
  int count = argc > 4 ? atoi (argv[4]) : 1;

  if (argc > 5)
    swipe_timeout_s = atoi (argv[5]);
  int rc = 1;
  gint64 t0;

  if (argc < 4)
    {
      g_printerr ("usage: vfs495-tool capture COMMANDS.bin OUT_PREFIX [COUNT [TIMEOUT_S]]\n");
      return 2;
    }
  cmds = vfs495_commands_load (argv[2], &error);
  if (!cmds)
    goto out;
  ctx = g_usb_context_new (&error);
  if (!ctx)
    goto out;
  usb = g_usb_context_find_by_vid_pid (ctx, 0x138a, 0x003f, &error);
  /* the sensor keeps patches from an earlier session unless it was suspended; a port reset
   * returns it to its power-on state (the driver does the same on open) */
  if (!usb || !g_usb_device_open (usb, &error) || !g_usb_device_reset (usb, &error) ||
      !g_usb_device_claim_interface (usb, 0, G_USB_DEVICE_CLAIM_INTERFACE_NONE, &error))
    goto out;

  s = vfs495_session_new (usb, cmds);
  t0 = g_get_monotonic_time ();
  if (!vfs495_session_open (s, &error))
    goto out;
  g_print ("session ready in %.2f s\n", (g_get_monotonic_time () - t0) / 1e6);

  for (int k = 1; k <= count; k++)
    {
      g_autoptr(GCancellable) cancel = g_cancellable_new ();
      g_autoptr(GByteArray) stream = NULL;
      g_autofree guint8 *lines = NULL;
      g_autofree guint8 *img = NULL;
      g_autofree char *pgm = g_strdup_printf ("%s.%d.pgm", argv[3], k);
      g_autofree char *raw = g_strdup_printf ("%s.%d.lines.raw", argv[3], k);
      GThread *timer;
      Vfs495AssembleInfo info;
      guint8 key[32], iv[16];
      int n;

      t0 = g_get_monotonic_time ();
      if (!vfs495_session_arm (s, &error))
        goto out;
      g_print ("[%d/%d] armed in %.2f s: swipe now\n", k, count, (g_get_monotonic_time () - t0) / 1e6);
      timer = g_thread_new ("timeout", cancel_after, cancel);
      if (!vfs495_session_wait_swipe (s, cancel, &stream, &error))
        {
          g_cancellable_cancel (cancel);
          g_thread_join (timer);
          if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            {
              g_print ("   no swipe within %d s\n", swipe_timeout_s);
              g_clear_error (&error);
              continue;
            }
          goto out;
        }
      g_cancellable_cancel (cancel);
      g_thread_join (timer);

      t0 = g_get_monotonic_time ();
      vfs495_session_image_key (s, key, iv);
      lines = vfs495_decode_stream (stream->data, stream->len, key, iv, cmds->descramble, &n, NULL, &error);
      if (!lines)
        goto out;
      write_lines_raw (raw, lines, n, NULL);
      img = vfs495_assemble (lines, n, &info, &error);
      g_print ("   region %d lines, trusted %d, confident %.0f%%, fast %.0f%%, median lag %.0f, still %.0f%%, "
               "coverage %.0f%% -> %s\n", info.region_lines, info.trusted, 100 * info.confident, 100 * info.fast,
               info.median_lag, 100 * info.still_fraction, 100 * info.coverage,
               vfs495_swipe_verdict_name (vfs495_swipe_verdict (img, &info)));
      if (!img)
        {
          g_print ("   %u bytes, %d lines: %s\n", stream->len, n, error->message);
          g_clear_error (&error);
          continue;
        }
      write_pgm (pgm, img, VFS495_MAIN_WIDTH, info.rows, NULL);
      g_print ("   %u bytes, %d lines -> %d rows (print lines %d-%d) in %.2f s: %s\n", stream->len, n,
               info.rows, info.first_line, info.last_line, (g_get_monotonic_time () - t0) / 1e6, pgm);
    }
  rc = 0;

out:
  if (error)
    g_printerr ("error: %s\n", error->message);
  if (s)
    {
      vfs495_session_close (s);
      vfs495_session_free (s);
    }
  if (usb)
    g_usb_device_close (usb, NULL);
  vfs495_commands_free (cmds);
  return rc;
}

int
main (int argc, char **argv)
{
  if (argc >= 2 && strcmp (argv[1], "assemble") == 0)
    return cmd_assemble (argc, argv);
  if (argc >= 2 && strcmp (argv[1], "capture") == 0)
    return cmd_capture (argc, argv);
  g_printerr ("usage: vfs495-tool assemble LINES.raw OUT.pgm\n"
              "       vfs495-tool capture COMMANDS.bin OUT_PREFIX [COUNT [TIMEOUT_S]]\n");
  return 2;
}
