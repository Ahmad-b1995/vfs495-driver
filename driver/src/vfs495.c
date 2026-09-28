/*
 * libfprint driver for the Validity VFS495 swipe sensor (138a:003f), built as a TOD module.
 *
 * The sensor needs its setup commands and firmware patches replayed from a command data file
 * (see driver/tools/make-commands.py), then a Validity SSLv3 session keyed with the RSA key
 * from its flash. Finger detection: arm with a fresh image key, poll the finger state, collect
 * the encrypted swipe stream, abort. The stream is decoded and stitched in a worker thread.
 * Protocol details are in the project README; the blocking equivalent is vfs495-proto.c.
 */
#define FP_COMPONENT "vfs495"

#include "drivers_api.h"

#include <openssl/rand.h>
#include <string.h>

#include "vfs495-assemble.h"
#include "vfs495-commands.h"
#include "vfs495-image.h"
#include "vfs495-protocol.h"

#define COMMANDS_PATH     "/var/lib/vfs495-driver/commands.bin"
#define CMD_TIMEOUT_MS    3000
#define REARM_AFTER_MS    50000   /* HP arms for at most 60 s; re-arm before that */
#define COLLECT_TICK_MS   20
#define MIN_ROWS          80      /* a usable swipe stitches to ~150-400 rows */

G_DECLARE_FINAL_TYPE (FpiDeviceVfs495, fpi_device_vfs495, FPI, DEVICE_VFS495, FpImageDevice)

struct _FpiDeviceVfs495
{
  FpImageDevice   parent;

  Vfs495Commands *cmds;
  Vfs495Crypto    crypto;
  gboolean        claimed;
  gboolean        session_open;
  gboolean        captured;        /* a capture ran since setup: send the re-arm block first */
  gboolean        open_retried;
  GByteArray     *flash;           /* pre-session flash block holding the RSA key */
  guint           cmd_index;       /* position while walking the command list */

  /* the command in flight (see run_cmd) */
  GByteArray     *cmd_out;
  guint8          cmd_byte;
  gboolean        cmd_decrypt;
  guint32         cmd_data_len;
  GByteArray     *reply;
  GByteArray     *data;

  /* capture loop */
  FpiSsm         *capture_ssm;
  gboolean        loop_running;
  gboolean        awaiting;        /* libfprint wants a finger and none was reported yet */
  gboolean        finger_reported;
  gboolean        deactivating;
  gboolean        suspending;
  gboolean        rearm;           /* armed too long: abort and arm again */
  gboolean        recovering;      /* one silent reset and setup after an error */
  gint64          arm_time;
  gint64          finger_time;
  guint8          image_key[32];
  guint8          image_iv[16];

  /* pending reads on the data endpoint (see VFS495_READ_LEN) */
  GCancellable   *read_cancel;
  GQueue          inflight;
  guint           pending;
  gboolean        reader_waiting;  /* the capture machine waits for pending reads to end */
  GByteArray     *stream;
  guint           stream_len;
  gint64          last_data;
  GError         *read_error;
};

G_DEFINE_TYPE (FpiDeviceVfs495, fpi_device_vfs495, FP_TYPE_IMAGE_DEVICE)

static void start_capture (FpiDeviceVfs495 *self);

static const Vfs495Command *
command (FpiDeviceVfs495 *self, guint i)
{
  return g_ptr_array_index (self->cmds->commands, i);
}

static const guint8 *
command_payload (const Vfs495Command *c, gsize *len)
{
  return g_bytes_get_data (c->payload, len);
}

/* ---- command runner ------------------------------------------------------------------------
 * One command: write it, read the reply (decrypted in session), read exactly the data the
 * sensor sends after it, and wait after flash reads. Runs as a sub-machine; the reply and
 * data are left in self->reply and self->data. */

enum {
  CMD_SEND,
  CMD_REPLY,
  CMD_DATA,
  CMD_SETTLE,
  CMD_NUM_STATES,
};

static void
cmd_reply_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  g_clear_pointer (&self->reply, g_byte_array_unref);
  if (self->cmd_decrypt)
    {
      self->reply = vfs495_crypto_open (&self->crypto, transfer->buffer, transfer->actual_length, &error);
      if (!self->reply)
        {
          fpi_ssm_mark_failed (transfer->ssm, error);
          return;
        }
    }
  else
    {
      self->reply = g_byte_array_new ();
      g_byte_array_append (self->reply, transfer->buffer, transfer->actual_length);
    }
  fpi_ssm_next_state (transfer->ssm);
}

static void
cmd_data_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if (transfer->actual_length != transfer->length)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "short data read after command %02x",
                                                     self->cmd_byte));
      return;
    }
  g_byte_array_append (self->data, transfer->buffer, transfer->actual_length);
  fpi_ssm_jump_to_state (transfer->ssm, CMD_DATA);
}

static void
cmd_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  FpiUsbTransfer *transfer;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CMD_SEND:
      transfer = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_bulk (transfer, VFS495_EP_OUT, self->cmd_out->len);
      memcpy (transfer->buffer, self->cmd_out->data, self->cmd_out->len);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer, CMD_TIMEOUT_MS, NULL, fpi_ssm_usb_transfer_cb, NULL);
      break;

    case CMD_REPLY:
      transfer = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_bulk (transfer, VFS495_EP_CMD_IN, VFS495_REPLY_MAX);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer, CMD_TIMEOUT_MS, NULL, cmd_reply_cb, NULL);
      break;

    case CMD_DATA:
      /* The sensor sends setup data in whole 64-byte packets with no terminating short
       * packet, so each request must be exact: a larger one only ends by timing out, and
       * GUsb drops the length of a timed-out transfer. */
      if (self->data->len < self->cmd_data_len)
        {
          gsize want = MIN (self->cmd_data_len - self->data->len, VFS495_DATA_CHUNK);

          transfer = fpi_usb_transfer_new (dev);
          fpi_usb_transfer_fill_bulk (transfer, VFS495_EP_DATA_IN, want);
          transfer->ssm = ssm;
          fpi_usb_transfer_submit (transfer, CMD_TIMEOUT_MS, NULL, cmd_data_cb, NULL);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      break;

    case CMD_SETTLE:
      if (self->cmd_byte == VFS495_CMD_FLASH_READ)
        fpi_ssm_mark_completed_delayed (ssm, VFS495_FLASH_SETTLE_MS);
      else
        fpi_ssm_mark_completed (ssm);
      break;
    }
}

/* out: the bytes to write (taken); cmd: the command byte, for status and settle handling */
static void
run_cmd_full (FpiSsm *parent, FpiDeviceVfs495 *self, GByteArray *out, guint8 cmd, gboolean decrypt,
              guint32 data_len)
{
  FpiSsm *ssm;

  g_clear_pointer (&self->cmd_out, g_byte_array_unref);
  g_clear_pointer (&self->reply, g_byte_array_unref);
  g_clear_pointer (&self->data, g_byte_array_unref);
  self->cmd_out = out;
  self->cmd_byte = cmd;
  self->cmd_decrypt = decrypt;
  self->cmd_data_len = data_len;
  self->data = g_byte_array_new ();

  ssm = fpi_ssm_new (FP_DEVICE (self), cmd_handler, CMD_NUM_STATES);
  fpi_ssm_silence_debug (ssm);
  fpi_ssm_start_subsm (parent, ssm);
}

/* a plaintext command before the session */
static void
run_plain (FpiSsm *parent, FpiDeviceVfs495 *self, const guint8 *payload, gsize len, guint32 data_len)
{
  GByteArray *out = g_byte_array_sized_new (len);

  g_byte_array_append (out, payload, len);
  run_cmd_full (parent, self, out, payload[0], FALSE, data_len);
}

/* an encrypted command inside the session */
static void
run_session (FpiSsm *parent, FpiDeviceVfs495 *self, const guint8 *payload, gsize len, guint32 data_len)
{
  run_cmd_full (parent, self, vfs495_crypto_seal (&self->crypto, 0x17, payload, len), payload[0], TRUE,
                data_len);
}

static gboolean
reply_ok (FpiDeviceVfs495 *self, FpiSsm *ssm)
{
  GError *error = NULL;

  if (vfs495_check_status (self->reply->data, self->reply->len, self->cmd_byte, &error))
    return TRUE;
  fpi_ssm_mark_failed (ssm, error);
  return FALSE;
}

/* next command of a phase from self->cmd_index on, or -1 */
static gint
next_command (FpiDeviceVfs495 *self, Vfs495Phase phase)
{
  for (guint i = self->cmd_index; i < self->cmds->commands->len; i++)
    if (command (self, i)->phase == phase)
      {
        self->cmd_index = i + 1;
        return i;
      }
  self->cmd_index = self->cmds->commands->len;
  return -1;
}

/* ---- session setup ---------------------------------------------------------------------------
 * Port reset, pre-session commands (patches and the flash reads that carry the RSA key),
 * handshake, configuration. The reset matters: the sensor keeps its patches from an earlier
 * session until it is suspended, and a fresh setup fails on a patched sensor. */

enum {
  SETUP_RESET,
  SETUP_PRE,
  SETUP_PRE_DONE,
  SETUP_HELLO,
  SETUP_KEY_EXCHANGE,
  SETUP_FINISH,
  SETUP_CONFIG,
  SETUP_CONFIG_DONE,
  SETUP_NUM_STATES,
};

static void
setup_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  GError *error = NULL;
  const guint8 *p;
  gsize len;
  gint i;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SETUP_RESET:
      self->session_open = FALSE;
      self->captured = FALSE;
      self->cmd_index = 0;
      vfs495_crypto_clear (&self->crypto);
      g_clear_pointer (&self->flash, g_byte_array_unref);
      if (self->claimed)
        g_usb_device_release_interface (usb, 0, 0, NULL);
      self->claimed = FALSE;
      if (!g_usb_device_reset (usb, &error) ||
          !g_usb_device_claim_interface (usb, 0, G_USB_DEVICE_CLAIM_INTERFACE_NONE, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      self->claimed = TRUE;
      fpi_ssm_next_state (ssm);
      break;

    case SETUP_PRE:
      i = next_command (self, VFS495_PHASE_PRE);
      if (i < 0)
        {
          fpi_ssm_jump_to_state (ssm, SETUP_HELLO);
          return;
        }
      p = command_payload (command (self, i), &len);
      run_plain (ssm, self, p, len, command (self, i)->data_len);
      break;

    case SETUP_PRE_DONE:
      if (self->cmd_byte == 0x01)
        {
          g_autofree char *hex = vfs495_hex_prefix (self->reply->data, self->reply->len, 40);
          fp_dbg ("sensor state %s", hex);
        }
      if (self->data->len == VFS495_FLASH_BLOCK_LEN)
        self->flash = g_byte_array_ref (self->data);
      fpi_ssm_jump_to_state (ssm, SETUP_PRE);
      break;

    case SETUP_HELLO:
      {
        GByteArray *hello;

        self->cmd_index = 0;
        i = next_command (self, VFS495_PHASE_HELLO);
        if (i < 0 || !self->flash)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                "%s", i < 0 ? "command file has no ClientHello" :
                                                                "sensor key not found in flash"));
            return;
          }
        hello = vfs495_crypto_hello (&self->crypto, command (self, i)->payload, &error);
        if (!hello)
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
        run_cmd_full (ssm, self, hello, 0x11, FALSE, 0);
      }
      break;

    case SETUP_KEY_EXCHANGE:
      {
        GByteArray *flight = vfs495_crypto_key_exchange (&self->crypto, self->reply->data, self->reply->len,
                                                         self->flash->data + VFS495_FLASH_KEY_OFFSET, &error);
        if (!flight)
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
        run_cmd_full (ssm, self, flight, 0x11, FALSE, 0);
      }
      break;

    case SETUP_FINISH:
      if (!vfs495_crypto_finish (&self->crypto, self->reply->data, self->reply->len, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      self->cmd_index = 0;
      fpi_ssm_next_state (ssm);
      break;

    case SETUP_CONFIG:
      i = next_command (self, VFS495_PHASE_SETUP);
      if (i < 0)
        {
          self->session_open = TRUE;
          fpi_ssm_mark_completed (ssm);
          return;
        }
      p = command_payload (command (self, i), &len);
      run_session (ssm, self, p, len, command (self, i)->data_len);
      break;

    case SETUP_CONFIG_DONE:
      if (reply_ok (self, ssm))
        fpi_ssm_jump_to_state (ssm, SETUP_CONFIG);
      break;
    }
}

static FpiSsm *
setup_ssm (FpiDeviceVfs495 *self)
{
  return fpi_ssm_new (FP_DEVICE (self), setup_handler, SETUP_NUM_STATES);
}

/* ---- data endpoint reader ------------------------------------------------------------------ */

typedef struct
{
  gboolean done;
  gssize   len;    /* -1 if the read failed or was cancelled */
  guint8  *buf;
} ReadSlot;

static void reader_submit (FpiDeviceVfs495 *self);

static void
read_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  ReadSlot *slot = user_data;

  slot->done = TRUE;
  if (error)
    {
      slot->len = -1;
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
          !g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_CANCELLED) && !self->read_error)
        {
          fp_warn ("data read failed: %s", error->message);
          self->read_error = g_steal_pointer (&error);
        }
      g_clear_error (&error);
    }
  else
    {
      slot->len = transfer->actual_length;
      slot->buf = g_memdup2 (transfer->buffer, transfer->actual_length);
    }
  self->pending--;

  /* completions arrive in order on one endpoint; the queue only guards the append order */
  while (!g_queue_is_empty (&self->inflight) && ((ReadSlot *) g_queue_peek_head (&self->inflight))->done)
    {
      ReadSlot *head = g_queue_pop_head (&self->inflight);

      if (head->len > 0)
        {
          g_byte_array_append (self->stream, head->buf, head->len);
          self->last_data = g_get_monotonic_time ();
        }
      if (head->len >= 0 && !g_cancellable_is_cancelled (self->read_cancel))
        reader_submit (self);
      g_free (head->buf);
      g_free (head);
    }

  if (self->pending == 0 && self->reader_waiting)
    {
      self->reader_waiting = FALSE;
      fpi_ssm_next_state (self->capture_ssm);
    }
}

static void
reader_submit (FpiDeviceVfs495 *self)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  ReadSlot *slot = g_new0 (ReadSlot, 1);

  fpi_usb_transfer_fill_bulk (transfer, VFS495_EP_DATA_IN, VFS495_READ_LEN);
  g_queue_push_tail (&self->inflight, slot);
  self->pending++;
  /* no timeout: see VFS495_READ_LEN */
  fpi_usb_transfer_submit (transfer, 0, self->read_cancel, read_cb, slot);
}

static void
reader_start (FpiDeviceVfs495 *self)
{
  g_clear_object (&self->read_cancel);
  g_clear_error (&self->read_error);
  g_clear_pointer (&self->stream, g_byte_array_unref);
  self->read_cancel = g_cancellable_new ();
  self->stream = g_byte_array_new ();
  self->last_data = g_get_monotonic_time ();
  for (int i = 0; i < VFS495_READ_QUEUE; i++)
    reader_submit (self);
}

/* ---- image processing (worker thread) ------------------------------------------------------ */

typedef struct
{
  GByteArray *stream;
  guint8      key[32];
  guint8      iv[16];
  guint16     descramble[VFS495_LINE_WIDTH];
} ProcessInput;

typedef struct
{
  guint8        *pixels;
  int            rows;
  FpDeviceRetry  retry;    /* when pixels is NULL */
} ProcessResult;

static void
process_input_free (gpointer p)
{
  ProcessInput *in = p;

  g_byte_array_unref (in->stream);
  explicit_bzero (in, sizeof *in);
  g_free (in);
}

static void
process_result_free (gpointer p)
{
  ProcessResult *res = p;

  g_free (res->pixels);
  g_free (res);
}

static void
process_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  ProcessInput *in = task_data;
  ProcessResult *res = g_new0 (ProcessResult, 1);
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *lines = NULL;
  Vfs495AssembleInfo info = { 0 };
  int n = 0;

  lines = vfs495_decode_stream (in->stream->data, in->stream->len, in->key, in->iv, in->descramble, &n, &error);
  if (!lines)
    {
      fp_warn ("swipe stream: %s", error->message);
      res->retry = FP_DEVICE_RETRY_GENERAL;
    }
  else if (!(res->pixels = vfs495_assemble (lines, n, &info, &error)))
    {
      fp_dbg ("swipe of %d lines: %s", n, error->message);
      res->retry = FP_DEVICE_RETRY_TOO_SHORT;
    }
  else if (info.rows < MIN_ROWS)
    {
      fp_dbg ("swipe of %d lines stitched to only %d rows", n, info.rows);
      g_clear_pointer (&res->pixels, g_free);
      res->retry = FP_DEVICE_RETRY_TOO_SHORT;
    }
  else
    {
      res->rows = info.rows;
      fp_dbg ("swipe of %d lines: print lines %d-%d, %d rows, %d bad columns, still %.0f%%", n, info.first_line,
              info.last_line, info.rows, info.bad_columns, 100 * info.still_fraction);
    }
  g_task_return_pointer (task, res, process_result_free);
}

static void
process_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (source);
  FpImageDevice *dev = FP_IMAGE_DEVICE (source);
  FpiSsm *ssm = user_data;
  ProcessResult *res = g_task_propagate_pointer (G_TASK (result), NULL);

  if (self->deactivating)
    {
      fp_dbg ("deactivated while processing; dropping the swipe");
    }
  else if (!res->pixels)
    {
      fpi_image_device_retry_scan (dev, res->retry);
    }
  else
    {
      FpImage *img = fp_image_new (VFS495_MAIN_WIDTH, res->rows);

      memcpy (img->data, res->pixels, (gsize) VFS495_MAIN_WIDTH * res->rows);
      fpi_image_device_image_captured (dev, img);
    }
  process_result_free (res);
  fpi_ssm_mark_completed (ssm);
}

/* ---- capture loop ---------------------------------------------------------------------------
 * Arm, poll until the sensor reports a finger or streams, collect until the data endpoint is
 * quiet, abort, stop the reads, process. Never send a command while the sensor may be
 * streaming: it resets. Deactivation and suspend are honoured while polling; a swipe in
 * progress is always collected first. */

enum {
  CAP_SESSION,
  CAP_ARM_BEGIN,
  CAP_ARM,
  CAP_ARM_DONE,
  CAP_READ_START,
  CAP_POLL,
  CAP_POLL_DONE,
  CAP_FINGER,
  CAP_COLLECT,
  CAP_ABORT,
  CAP_STOP_READER,
  CAP_PROCESS,
  CAP_NUM_STATES,
};

static void
capture_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  gint64 now = g_get_monotonic_time ();
  const guint8 *p;
  gsize len;
  gint i;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAP_SESSION:
      if (self->session_open)
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_start_subsm (ssm, setup_ssm (self));
      break;

    case CAP_ARM_BEGIN:
      self->cmd_index = 0;
      fpi_ssm_next_state (ssm);
      break;

    case CAP_ARM:
      /* the re-arm block (only after a capture), then the arming command with a fresh key */
      i = -1;
      while (i < 0 && self->cmd_index < self->cmds->commands->len)
        {
          const Vfs495Command *c = command (self, self->cmd_index++);

          if (c->phase == VFS495_PHASE_ARM || (c->phase == VFS495_PHASE_REARM && self->captured))
            i = self->cmd_index - 1;
        }
      if (i < 0)
        {
          fpi_ssm_jump_to_state (ssm, CAP_READ_START);
          return;
        }
      p = command_payload (command (self, i), &len);
      if (command (self, i)->phase == VFS495_PHASE_ARM)
        {
          g_autofree guint8 *armed = g_memdup2 (p, len);
          guint16 off = command (self, i)->key_offset;

          if (off == VFS495_NO_KEY || (gsize) off + 64 > len || RAND_bytes (self->image_key, 32) != 1 ||
              RAND_bytes (self->image_iv, 16) != 1 || RAND_bytes (armed + off + 48, 16) != 1)
            {
              fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                  "cannot set the image key"));
              return;
            }
          /* the image stream is encrypted with key = field bytes 0-31, IV = bytes 32-47 */
          memcpy (armed + off, self->image_key, 32);
          memcpy (armed + off + 32, self->image_iv, 16);
          run_session (ssm, self, armed, len, command (self, i)->data_len);
          explicit_bzero (armed, len);
        }
      else
        {
          run_session (ssm, self, p, len, command (self, i)->data_len);
        }
      break;

    case CAP_ARM_DONE:
      if (reply_ok (self, ssm))
        fpi_ssm_jump_to_state (ssm, CAP_ARM);
      break;

    case CAP_READ_START:
      self->captured = TRUE;
      self->arm_time = now;
      reader_start (self);
      fp_dbg ("armed: waiting for a finger");
      fpi_ssm_next_state (ssm);
      break;

    case CAP_POLL:
      if (self->stream->len > 0 || self->read_error)
        {
          fpi_ssm_jump_to_state (ssm, CAP_FINGER);
        }
      else if (self->deactivating || self->suspending)
        {
          fpi_ssm_jump_to_state (ssm, CAP_ABORT);
        }
      else if (now - self->arm_time > (gint64) REARM_AFTER_MS * 1000)
        {
          fp_dbg ("armed for %d s without a finger: arming again", REARM_AFTER_MS / 1000);
          self->rearm = TRUE;
          fpi_ssm_jump_to_state (ssm, CAP_ABORT);
        }
      else
        {
          const guint8 poll = VFS495_CMD_FINGER_STATE;
          run_session (ssm, self, &poll, 1, 0);
        }
      break;

    case CAP_POLL_DONE:
      if (!reply_ok (self, ssm))
        return;
      /* byte 0 after the status becomes 02 when the sensor starts a capture */
      if (self->reply->len > 2 && self->reply->data[2] != 0)
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_jump_to_state_delayed (ssm, CAP_POLL, VFS495_POLL_INTERVAL_MS);
      break;

    case CAP_FINGER:
      self->awaiting = FALSE;
      self->finger_reported = TRUE;
      self->finger_time = now;
      self->last_data = MAX (self->last_data, now);
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
      fpi_ssm_next_state (ssm);
      break;

    case CAP_COLLECT:
      /* A short read is not the end of a swipe: the sensor flushes a short packet whenever it
       * pauses. The swipe has ended when the endpoint stays quiet. */
      if (self->read_error || now - self->last_data >= (gint64) VFS495_SWIPE_QUIET_MS * 1000 ||
          now - self->finger_time >= (gint64) VFS495_SWIPE_LIMIT_MS * 1000)
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_jump_to_state_delayed (ssm, CAP_COLLECT, COLLECT_TICK_MS);
      break;

    case CAP_ABORT:
      /* without a finger the sensor pushes one frame before it replies; the pending reads
       * take it, and it is cut off below */
      {
        const guint8 abort_cmd = VFS495_CMD_ABORT;

        self->stream_len = self->stream->len;
        run_session (ssm, self, &abort_cmd, 1, 0);
      }
      break;

    case CAP_STOP_READER:
      fp_dbg ("abort: status %02x%02x; stream %u bytes, %u after the abort", self->reply->len > 1 ? self->reply->data[1] : 0,
              self->reply->len > 0 ? self->reply->data[0] : 0, self->stream_len, self->stream->len - self->stream_len);
      g_cancellable_cancel (self->read_cancel);
      if (self->pending == 0)
        fpi_ssm_next_state (ssm);
      else
        self->reader_waiting = TRUE;
      break;

    case CAP_PROCESS:
      if (self->read_error)
        {
          fpi_ssm_mark_failed (ssm, g_steal_pointer (&self->read_error));
          return;
        }
      g_byte_array_set_size (self->stream, self->stream_len);
      if (!self->finger_reported || self->deactivating)
        {
          fpi_ssm_mark_completed (ssm);
        }
      else
        {
          g_autoptr(GTask) task = g_task_new (dev, NULL, process_done, ssm);
          ProcessInput *in = g_new0 (ProcessInput, 1);

          in->stream = g_steal_pointer (&self->stream);
          memcpy (in->key, self->image_key, 32);
          memcpy (in->iv, self->image_iv, 16);
          memcpy (in->descramble, self->cmds->descramble, sizeof in->descramble);
          g_task_set_task_data (task, in, process_input_free);
          g_task_run_in_thread (task, process_thread);
        }
      break;
    }
}

static void
capture_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);
  gboolean reported = self->finger_reported;

  self->loop_running = FALSE;
  self->capture_ssm = NULL;
  self->finger_reported = FALSE;
  g_clear_object (&self->read_cancel);
  g_clear_pointer (&self->stream, g_byte_array_unref);

  if (error)
    {
      /* the sensor's state is unknown: the next capture starts with a port reset and setup */
      self->session_open = FALSE;
      if (!self->deactivating && !self->suspending)
        {
          if (!reported && !self->recovering)
            {
              fp_warn ("capture failed (%s); resetting the sensor and trying again", error->message);
              self->recovering = TRUE;
              g_error_free (error);
              start_capture (self);
              return;
            }
          if (!reported)
            {
              fpi_image_device_session_error (img_dev, error);
              return;
            }
          fp_warn ("capture failed during a swipe: %s", error->message);
          fpi_image_device_retry_scan (img_dev, FP_DEVICE_RETRY_GENERAL);
        }
      else
        {
          fp_dbg ("capture failed while stopping: %s", error->message);
        }
      g_error_free (error);
    }
  else if (reported)
    {
      self->recovering = FALSE;
    }

  if (reported)
    fpi_image_device_report_finger_status (img_dev, FALSE);

  if (self->suspending)
    {
      /* the sensor loses power in suspend; set it up again after resume */
      self->session_open = FALSE;
      fpi_device_suspend_complete (dev, NULL);
    }
  if (self->deactivating)
    {
      self->deactivating = FALSE;
      fpi_image_device_deactivate_complete (img_dev, NULL);
      return;
    }
  if (self->rearm && !self->suspending)
    {
      self->rearm = FALSE;
      start_capture (self);
    }
}

static void
start_capture (FpiDeviceVfs495 *self)
{
  g_assert (!self->loop_running);
  self->loop_running = TRUE;
  self->rearm = FALSE;
  self->capture_ssm = fpi_ssm_new (FP_DEVICE (self), capture_handler, CAP_NUM_STATES);
  fpi_ssm_start (self->capture_ssm, capture_done);
}

/* ---- close ------------------------------------------------------------------------------- */

enum {
  CLOSE_CMD,
  CLOSE_CMD_DONE,
  CLOSE_NOTIFY,
  CLOSE_NOTIFY_DONE,
  CLOSE_NUM_STATES,
};

static void
close_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  const guint8 notify[2] = { 0x01, 0x00 };
  const guint8 *p;
  gsize len;
  gint i;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CLOSE_CMD:
      /* HP's ending: unload the session patch and reload the pre-session one */
      i = next_command (self, VFS495_PHASE_CLOSE);
      if (i < 0)
        {
          fpi_ssm_jump_to_state (ssm, CLOSE_NOTIFY);
          return;
        }
      p = command_payload (command (self, i), &len);
      run_session (ssm, self, p, len, command (self, i)->data_len);
      break;

    case CLOSE_CMD_DONE:
      if (reply_ok (self, ssm))
        fpi_ssm_jump_to_state (ssm, CLOSE_CMD);
      break;

    case CLOSE_NOTIFY:
      run_cmd_full (ssm, self, vfs495_crypto_seal (&self->crypto, 0x15, notify, 2), 0x15, FALSE, 0);
      break;

    case CLOSE_NOTIFY_DONE:
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
close_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (error)
    {
      fp_dbg ("closing the session: %s", error->message);
      g_error_free (error);
    }
  self->session_open = FALSE;
  vfs495_crypto_clear (&self->crypto);
  if (self->claimed)
    g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, NULL);
  self->claimed = FALSE;
  g_clear_pointer (&self->flash, g_byte_array_unref);
  g_clear_pointer (&self->cmd_out, g_byte_array_unref);
  g_clear_pointer (&self->reply, g_byte_array_unref);
  g_clear_pointer (&self->data, g_byte_array_unref);
  g_clear_pointer (&self->cmds, vfs495_commands_free);
  fpi_image_device_close_complete (FP_IMAGE_DEVICE (dev), NULL);
}

/* ---- device vfuncs ------------------------------------------------------------------------- */

static void
open_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (error && !self->open_retried)
    {
      /* seen once in testing: the sensor dropped off the bus right after the port reset */
      fp_warn ("sensor setup failed (%s); trying once more", error->message);
      g_error_free (error);
      self->open_retried = TRUE;
      fpi_ssm_start (setup_ssm (self), open_done);
      return;
    }
  if (error)
    {
      if (self->claimed)
        g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, NULL);
      self->claimed = FALSE;
      g_clear_pointer (&self->cmds, vfs495_commands_free);
    }
  fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
dev_open (FpImageDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);
  const char *path = g_getenv ("VFS495_COMMANDS");
  GError *error = NULL;

  self->cmds = vfs495_commands_load (path ? path : COMMANDS_PATH, &error);
  if (!self->cmds)
    {
      fpi_image_device_open_complete (dev, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                     "VFS495 command data: %s", error->message));
      g_error_free (error);
      return;
    }
  self->open_retried = FALSE;
  fpi_ssm_start (setup_ssm (self), open_done);
}

static void
dev_close (FpImageDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (!self->session_open)
    {
      close_done (NULL, FP_DEVICE (dev), NULL);
      return;
    }
  self->cmd_index = 0;
  fpi_ssm_start (fpi_ssm_new (FP_DEVICE (dev), close_handler, CLOSE_NUM_STATES), close_done);
}

static void
dev_activate (FpImageDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  self->deactivating = FALSE;
  self->recovering = FALSE;
  fpi_image_device_activate_complete (dev, NULL);
}

static void
dev_change_state (FpImageDevice *dev, FpiImageDeviceState state)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  if (state != FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    return;
  self->awaiting = TRUE;
  if (!self->loop_running && !self->suspending)
    start_capture (self);
}

static void
dev_deactivate (FpImageDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  self->awaiting = FALSE;
  if (self->loop_running)
    self->deactivating = TRUE;
  else
    fpi_image_device_deactivate_complete (dev, NULL);
}

static void
dev_suspend (FpDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  self->suspending = TRUE;
  if (!self->loop_running)
    {
      self->session_open = FALSE;
      fpi_device_suspend_complete (dev, NULL);
    }
  /* otherwise the capture loop stops at its next poll and completes the suspend */
}

static void
dev_resume (FpDevice *dev)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (dev);

  self->suspending = FALSE;
  self->session_open = FALSE;
  if (self->awaiting && !self->loop_running)
    start_capture (self);
  fpi_device_resume_complete (dev, NULL);
}

static const FpIdEntry id_table[] = {
  { .vid = 0x138a, .pid = 0x003f },
  { .vid = 0, .pid = 0 },
};

static void
fpi_device_vfs495_finalize (GObject *object)
{
  FpiDeviceVfs495 *self = FPI_DEVICE_VFS495 (object);

  vfs495_crypto_clear (&self->crypto);
  g_clear_pointer (&self->cmds, vfs495_commands_free);
  g_clear_pointer (&self->flash, g_byte_array_unref);
  g_clear_pointer (&self->cmd_out, g_byte_array_unref);
  g_clear_pointer (&self->reply, g_byte_array_unref);
  g_clear_pointer (&self->data, g_byte_array_unref);
  g_clear_pointer (&self->stream, g_byte_array_unref);
  g_clear_object (&self->read_cancel);
  g_clear_error (&self->read_error);
  G_OBJECT_CLASS (fpi_device_vfs495_parent_class)->finalize (object);
}

static void
fpi_device_vfs495_init (FpiDeviceVfs495 *self)
{
  g_queue_init (&self->inflight);
}

static void
fpi_device_vfs495_class_init (FpiDeviceVfs495Class *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_vfs495_finalize;

  dev_class->id = "vfs495";
  dev_class->full_name = "Validity VFS495";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_SWIPE;
  dev_class->suspend = dev_suspend;
  dev_class->resume = dev_resume;

  img_class->img_open = dev_open;
  img_class->img_close = dev_close;
  img_class->activate = dev_activate;
  img_class->change_state = dev_change_state;
  img_class->deactivate = dev_deactivate;
  img_class->img_width = VFS495_MAIN_WIDTH;
  img_class->img_height = -1;
}

/* The driver's GType is registered statically and can never be unregistered, so the module
 * must stay loaded: libfprint closes TOD modules when its context is freed, and a device
 * object that outlives the context would then call into unmapped code. */
G_MODULE_EXPORT const gchar *
g_module_check_init (GModule *module)
{
  g_module_make_resident (module);
  return NULL;
}

/* the TOD loader's entry point */
G_MODULE_EXPORT GType
fpi_tod_shared_driver_get_type (void)
{
  return fpi_device_vfs495_get_type ();
}
