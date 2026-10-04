#include "vfs495-proto.h"

#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "vfs495-protocol.h"

#define CMD_TIMEOUT_MS  3000

/* ---- session --------------------------------------------------------------------------- */

struct _Vfs495Session
{
  GUsbDevice           *usb;
  const Vfs495Commands *cmds;
  Vfs495Crypto          crypto;
  gboolean              open;
  gboolean              captured;      /* a capture ran since setup: re-arm before arming */
  guint8                image_key[32];
  guint8                image_iv[16];
  GByteArray           *flash;         /* pre-session flash block: RSA key, patch signatures */
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
  g_clear_pointer (&s->flash, g_byte_array_unref);
  vfs495_crypto_clear (&s->crypto);
  explicit_bzero (s, sizeof *s);
  g_free (s);
}

static gboolean
usb_write (Vfs495Session *s, const guint8 *data, gsize len, GError **error)
{
  gsize actual = 0;

  if (!g_usb_device_bulk_transfer (s->usb, VFS495_EP_OUT, (guint8 *) data, len, &actual, CMD_TIMEOUT_MS, NULL, error))
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
  GByteArray *buf = g_byte_array_sized_new (VFS495_DATA_CHUNK);
  gsize actual = 0;

  g_byte_array_set_size (buf, VFS495_DATA_CHUNK);
  if (!g_usb_device_bulk_transfer (s->usb, VFS495_EP_CMD_IN, buf->data, VFS495_DATA_CHUNK, &actual, timeout, NULL, error))
    {
      g_byte_array_unref (buf);
      return NULL;
    }
  g_byte_array_set_size (buf, actual);
  return buf;
}

typedef struct
{
  GUsbDevice   *usb;
  GCancellable *cancel;
  GQueue        inflight;   /* Read, in submission order */
  GByteArray   *out;
  guint         short_reads; /* the sensor ends a read short whenever it pauses, also mid-stream */
  gint64        last_data;  /* monotonic time of the last data */
  gint64        started;    /* when the reads were queued (just after arming) */
  gint64        first_data; /* when the first data arrived, 0 before */
  GString      *gaps;       /* diagnostics: pauses over 25 ms, as offset:ms */
  guint         max_gap_ms;
  GError       *error;
} Reader;

typedef struct
{
  Reader  *reader;
  guint8   buf[VFS495_READ_LEN];
  gboolean done;
  gssize   len;             /* -1 if the read failed or was cancelled */
} Read;

static void reader_submit (Reader *r);

static void
read_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
  Read *rd = user_data;
  Reader *r = rd->reader;
  g_autoptr(GError) error = NULL;

  rd->len = g_usb_device_bulk_transfer_finish (G_USB_DEVICE (source), res, &error);
  rd->done = TRUE;
  if (rd->len < 0 && !g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_CANCELLED) &&
      !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) && !r->error)
    {
      g_debug ("data read failed: %s", error->message);
      r->error = g_steal_pointer (&error);
    }

  /* completions arrive in order on one endpoint; the queue only guards the append order */
  while (!g_queue_is_empty (&r->inflight) && ((Read *) g_queue_peek_head (&r->inflight))->done)
    {
      Read *head = g_queue_pop_head (&r->inflight);

      if (head->len > 0)
        {
          gint64 now = g_get_monotonic_time ();
          guint gap_ms = (guint) ((now - r->last_data) / 1000);

          if (r->out->len > 0 && gap_ms > 25)
            g_string_append_printf (r->gaps, " %u:%u", r->out->len / 272, gap_ms);
          if (r->out->len > 0)
            r->max_gap_ms = MAX (r->max_gap_ms, gap_ms);
          if (!r->first_data)
            r->first_data = now;
          g_byte_array_append (r->out, head->buf, (guint) head->len);
          r->last_data = now;
        }
      if (head->len >= 0 && head->len < VFS495_READ_LEN)
        r->short_reads++;
      if (head->len >= 0 && !g_cancellable_is_cancelled (r->cancel))
        reader_submit (r);
      g_free (head);
    }
}

static void
reader_submit (Reader *r)
{
  Read *rd = g_new0 (Read, 1);

  rd->reader = r;
  g_queue_push_tail (&r->inflight, rd);
  g_usb_device_bulk_transfer_async (r->usb, VFS495_EP_DATA_IN, rd->buf, VFS495_READ_LEN, 0, r->cancel, read_cb, rd);
}

static Reader *
reader_start (GUsbDevice *usb)
{
  Reader *r = g_new0 (Reader, 1);

  r->usb = usb;
  r->cancel = g_cancellable_new ();
  r->out = g_byte_array_new ();
  r->last_data = r->started = g_get_monotonic_time ();
  r->gaps = g_string_new (NULL);
  g_queue_init (&r->inflight);
  for (int i = 0; i < VFS495_READ_QUEUE; i++)
    reader_submit (r);
  return r;
}

/* run the main context for `ms` milliseconds, delivering read completions */
static void
pump (guint ms)
{
  gint64 end = g_get_monotonic_time () + (gint64) ms * 1000;

  while (g_get_monotonic_time () < end)
    {
      while (g_main_context_iteration (NULL, FALSE))
        ;
      g_usleep (500);
    }
}

/* cancel the pending reads (only ever while the sensor is not sending) and wait for them */
static GByteArray *
reader_stop (Reader *r, GError **error)
{
  GByteArray *out;

  g_cancellable_cancel (r->cancel);
  while (!g_queue_is_empty (&r->inflight))
    g_main_context_iteration (NULL, TRUE);
  out = r->out;
  if (r->error)
    {
      g_propagate_error (error, r->error);
      g_byte_array_unref (out);
      out = NULL;
    }
  g_object_unref (r->cancel);
  g_string_free (r->gaps, TRUE);
  g_free (r);
  return out;
}

/*
 * Read exactly `len` bytes of setup data. The sensor sends these blocks in whole 64-byte
 * packets without a terminating short packet, so every request must be exact: a larger
 * request only ends by timing out, and GUsb drops the byte count of a timed-out transfer.
 */
static gboolean
read_setup_data (Vfs495Session *s, gsize len, GByteArray *out, GError **error)
{
  gsize start = out->len;

  g_byte_array_set_size (out, start + len);
  for (gsize done = 0; done < len;)
    {
      gsize want = MIN (len - done, VFS495_DATA_CHUNK);
      gsize actual = 0;

      if (!g_usb_device_bulk_transfer (s->usb, VFS495_EP_DATA_IN, out->data + start + done, want, &actual,
                                       CMD_TIMEOUT_MS, NULL, error))
        return FALSE;
      if (actual != want)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "short data read (%zu of %zu)", done + actual,
                       len);
          return FALSE;
        }
      done += actual;
    }
  return TRUE;
}

/* see VFS495_FLASH_SETTLE_MS */
static void
settle_after (guint8 cmd)
{
  if (cmd == VFS495_CMD_FLASH_READ)
    g_usleep (VFS495_FLASH_SETTLE_MS * 1000);
}

/* encrypted command; returns the decrypted reply (status u16 LE + data) */
static GByteArray *
session_cmd (Vfs495Session *s, const guint8 *payload, gsize len, guint timeout, GError **error)
{
  g_autoptr(GByteArray) rec = vfs495_crypto_seal (&s->crypto, 0x17, payload, len);
  g_autoptr(GByteArray) resp = NULL;

  if (!usb_write (s, rec->data, rec->len, error))
    return NULL;
  resp = usb_read_cmd (s, timeout, error);
  if (!resp)
    return NULL;
  return vfs495_crypto_open (&s->crypto, resp->data, resp->len, error);
}

static gboolean
check_status (const GByteArray *reply, guint8 cmd, GError **error)
{
  return vfs495_check_status (reply->data, reply->len, cmd, error);
}

static gboolean
handshake (Vfs495Session *s, const guint8 modulus[VFS495_RSA_LEN], GBytes *hello_tpl, GError **error)
{
  g_autoptr(GByteArray) hello = vfs495_crypto_hello (&s->crypto, hello_tpl, error);
  g_autoptr(GByteArray) sh = NULL;
  g_autoptr(GByteArray) flight = NULL;
  g_autoptr(GByteArray) resp = NULL;

  if (!hello || !usb_write (s, hello->data, hello->len, error) ||
      !(sh = usb_read_cmd (s, CMD_TIMEOUT_MS, error)) ||
      !(flight = vfs495_crypto_key_exchange (&s->crypto, sh->data, sh->len, modulus, error)) ||
      !usb_write (s, flight->data, flight->len, error) ||
      !(resp = usb_read_cmd (s, CMD_TIMEOUT_MS, error)))
    return FALSE;
  return vfs495_crypto_finish (&s->crypto, resp->data, resp->len, error);
}

/* a command's bytes as sent; for a signed patch, the form this sensor takes */
static guint8 *
command_bytes (Vfs495Session *s, const Vfs495Command *c, gsize *len, GError **error)
{
  const guint8 *p = g_bytes_get_data (c->payload, len);

  if (!(c->flags & VFS495_FLAG_FLASH_SIGNATURE))
    return g_memdup2 (p, *len);
  return vfs495_patch_for_sensor (p, *len, s->flash ? s->flash->data : NULL, s->flash ? s->flash->len : 0, len, error);
}

gboolean
vfs495_session_open (Vfs495Session *s, GError **error)
{
  GBytes *hello = NULL;

  /* experiments: VFS495_SKIP="9,15" leaves out commands by file index; VFS495_TIMING prints
   * how long each command takes */
  g_auto(GStrv) skip = g_strsplit (g_getenv ("VFS495_SKIP") ? g_getenv ("VFS495_SKIP") : "", ",", -1);
  gboolean timing = g_getenv ("VFS495_TIMING") != NULL;

  s->open = FALSE;
  s->captured = FALSE;
  for (guint i = 0; i < s->cmds->commands->len; i++)
    {
      Vfs495Command *c = g_ptr_array_index (s->cmds->commands, i);
      g_autofree char *index = g_strdup_printf ("%u", i);
      gint64 t0 = g_get_monotonic_time ();
      gsize len;
      g_autofree guint8 *p = NULL;

      if (g_strv_contains ((const char *const *) skip, index))
        {
          if (timing)
            g_print ("   #%-2u skipped\n", i);
          continue;
        }
      if ((c->phase == VFS495_PHASE_PRE || c->phase == VFS495_PHASE_SETUP) && !(p = command_bytes (s, c, &len, error)))
        return FALSE;
      if (c->phase == VFS495_PHASE_PRE)
        {
          g_autoptr(GByteArray) reply = NULL;
          g_autoptr(GByteArray) data = g_byte_array_new ();

          if (!usb_write (s, p, len, error) || !(reply = usb_read_cmd (s, CMD_TIMEOUT_MS, error)))
            return FALSE;
          if (!read_setup_data (s, c->data_len, data, error))
            return FALSE;
          settle_after (p[0]);
          {
            g_autofree char *hex = vfs495_hex_prefix (reply->data, reply->len, 40);
            g_debug ("pre-session %02x (%zu bytes): reply %s, data %u bytes", p[0], len, hex, data->len);
          }
          if (data->len == VFS495_FLASH_BLOCK_LEN)
            {
              g_clear_pointer (&s->flash, g_byte_array_unref);
              s->flash = g_byte_array_ref (data);
            }
        }
      else if (c->phase == VFS495_PHASE_HELLO)
        {
          hello = c->payload;
          if (!s->flash)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "sensor key not found in flash");
              return FALSE;
            }
          if (!handshake (s, s->flash->data + VFS495_FLASH_KEY_OFFSET, hello, error))
            return FALSE;
        }
      else if (c->phase == VFS495_PHASE_SETUP)
        {
          g_autoptr(GByteArray) reply = session_cmd (s, p, len, CMD_TIMEOUT_MS, error);
          g_autoptr(GByteArray) data = g_byte_array_new ();

          if (!reply || !check_status (reply, p[0], error))
            return FALSE;
          if (!read_setup_data (s, c->data_len, data, error))
            return FALSE;
          settle_after (p[0]);
        }
      if (timing && c->phase <= VFS495_PHASE_SETUP)
        g_print ("   #%-2u %-5s %02x %6zu B + %6u B data: %6.1f ms\n", i,
                 c->phase == VFS495_PHASE_PRE ? "pre" : c->phase == VFS495_PHASE_HELLO ? "hello" : "setup",
                 p ? p[0] : 0x11, p ? len : 0, c->data_len, (g_get_monotonic_time () - t0) / 1000.0);
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
      guint8 cmd;
      g_autofree guint8 *payload = NULL;
      g_autoptr(GByteArray) reply = NULL;
      g_autoptr(GByteArray) data = g_byte_array_new ();

      if (!(c->phase == VFS495_PHASE_ARM || (c->phase == VFS495_PHASE_REARM && s->captured)))
        continue;
      if (!(payload = command_bytes (s, c, &len, error)))
        return FALSE;
      if (c->phase == VFS495_PHASE_ARM)
        {
          if (c->key_offset == VFS495_NO_KEY || (gsize) c->key_offset + VFS495_KEY_FIELD_LEN > len ||
              RAND_bytes (s->image_key, 32) != 1 || RAND_bytes (s->image_iv, 16) != 1 ||
              RAND_bytes (payload + c->key_offset + 48, VFS495_KEY_FIELD_LEN - 48) != 1)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "cannot set the image key");
              return FALSE;
            }
          memcpy (payload + c->key_offset, s->image_key, 32);
          memcpy (payload + c->key_offset + 32, s->image_iv, 16);
        }
      cmd = payload[0];
      reply = session_cmd (s, payload, len, CMD_TIMEOUT_MS, error);
      explicit_bzero (payload, len);
      if (!reply || !check_status (reply, cmd, error))
        return FALSE;
      if (!read_setup_data (s, c->data_len, data, error))
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

/* abort a capture. Without a finger the sensor pushes one frame before it replies; the
 * reader's pending reads take it. */
static gboolean
abort_capture (Vfs495Session *s, GError **error)
{
  const guint8 cmd = VFS495_CMD_ABORT;
  g_autoptr(GByteArray) reply = session_cmd (s, &cmd, 1, CMD_TIMEOUT_MS, error);

  if (reply)
    g_debug ("abort: status %02x%02x", reply->len > 1 ? reply->data[1] : 0xff, reply->len > 0 ? reply->data[0] : 0xff);
  return reply != NULL;
}

gboolean
vfs495_session_wait_swipe (Vfs495Session *s, GCancellable *cancellable, GByteArray **stream,
                           GError **error)
{
  const guint8 poll = VFS495_CMD_FINGER_STATE;
  Reader *r = reader_start (s->usb);
  g_autoptr(GByteArray) out = NULL;
  g_autoptr(GError) local = NULL;
  gint64 end;
  guint stream_len, r_short_reads, max_gap_ms;
  gint64 first_ms;
  g_autofree char *gaps = NULL;
  /* VFS495_QUIET_MS overrides both windows, to measure pauses */
  const char *quiet_env = g_getenv ("VFS495_QUIET_MS");
  gboolean ok = TRUE;

  *stream = NULL;
  /* Poll finger state until the sensor starts a capture (byte 0 after the status becomes 02)
   * or data arrives. Never send a command while the sensor may be streaming: it resets. */
  /* The armed sensor streams a swipe by itself; finger-state polls (HP's method) only risk
   * a command arriving as a stream starts. VFS495_POLL=1 polls like HP, for experiments. */
  while (!g_getenv ("VFS495_POLL") && !g_cancellable_is_cancelled (cancellable) && !r->out->len && !r->error)
    pump (VFS495_POLL_INTERVAL_MS);
  while (g_getenv ("VFS495_POLL") && !g_cancellable_is_cancelled (cancellable))
    {
      g_autoptr(GByteArray) state = session_cmd (s, &poll, 1, CMD_TIMEOUT_MS, &local);

      if (!state || !check_status (state, poll, &local))
        {
          ok = FALSE;
          break;
        }
      pump (0);
      if (state->len > 2 && (state->data[2] | state->data[3] | state->data[4] | state->data[5] | state->data[6]))
        g_debug ("finger state %02x %02x %02x %02x %02x", state->data[2], state->data[3], state->data[4],
                 state->data[5], state->data[6]);
      if (r->out->len > 0 || r->error || (state->len > 2 && state->data[2] != 0))
        break;
      pump (VFS495_POLL_INTERVAL_MS);
      if (r->out->len > 0 || r->error)
        break;
    }

  g_debug ("polling stopped: %u bytes so far%s", r->out->len, local ? ", poll failed" : "");
  /* Collect until the endpoint stays quiet. A short read is not an end marker: the sensor
   * flushes a short packet whenever it pauses, including early in a swipe. */
  if (ok && !g_cancellable_is_cancelled (cancellable))
    {
      r->last_data = g_get_monotonic_time ();
      end = r->last_data + (gint64) VFS495_SWIPE_LIMIT_MS * 1000;
      while (!r->error && g_get_monotonic_time () < end &&
             g_get_monotonic_time () - r->last_data <
               (gint64) 1000 * (quiet_env ? (guint) atoi (quiet_env) :
                                r->out->len < VFS495_SWIPE_START_BYTES ? VFS495_SWIPE_QUIET_START_MS :
                                VFS495_SWIPE_QUIET_MS))
        pump (5);
    }
  stream_len = r->out->len;
  r_short_reads = r->short_reads;
  max_gap_ms = r->max_gap_ms;
  first_ms = r->first_data ? (r->first_data - r->started) / 1000 : -1;
  gaps = g_strdup (r->gaps->str);

  if (!abort_capture (s, ok ? &local : NULL))
    ok = FALSE;
  pump (0);
  out = reader_stop (r, ok ? &local : NULL);
  if (!out)
    ok = FALSE;
  if (!ok)
    {
      g_propagate_error (error, g_steal_pointer (&local));
      return FALSE;
    }
  g_debug ("stream %u bytes in %u short reads, %u more after the abort", stream_len, r_short_reads,
           out->len - stream_len);
  if (stream_len > 0)
    g_print ("   first data %" G_GINT64_FORMAT " ms after arming; pauses: longest %u ms; over 25 ms at frame:ms%s\n",
             first_ms, max_gap_ms, *gaps ? gaps : " none");
  g_byte_array_set_size (out, stream_len);
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
  for (guint i = 0; i < s->cmds->commands->len; i++)
    {
      Vfs495Command *c = g_ptr_array_index (s->cmds->commands, i);
      g_autoptr(GByteArray) reply = NULL;
      g_autoptr(GError) error = NULL;
      gsize len;
      g_autofree guint8 *p = NULL;

      if (c->phase != VFS495_PHASE_CLOSE)
        continue;
      if (!(p = command_bytes (s, c, &len, &error)))
        {
          g_debug ("closing command: %s", error->message);
          continue;
        }
      reply = session_cmd (s, p, len, CMD_TIMEOUT_MS, &error);
      if (!reply || !check_status (reply, p[0], &error))
        g_debug ("closing command %02x: %s", p[0], error->message);
    }
  rec = vfs495_crypto_seal (&s->crypto, 0x15, notify, 2);
  if (usb_write (s, rec->data, rec->len, NULL))
    resp = usb_read_cmd (s, 1000, NULL);
  s->open = FALSE;
}
