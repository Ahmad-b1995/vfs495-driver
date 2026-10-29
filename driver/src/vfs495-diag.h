/*
 * Beta diagnostics: an opt-in record of every swipe and session event, for improving the
 * driver from real use. Off unless the diagnostics folder exists and its "until" file names a
 * time in the future (vfs495-diag on|off|status|bundle, driver/tools/diag.sh).
 *
 * DIR/events.log      one line per session event: wall clock, milliseconds since open, text
 * DIR/SWIPE/          per swipe, named by its time:
 *   swipe.json        verdict, the stitcher's measurements, timings and sensor status
 *   stream.dec        the decrypted swipe stream (272-byte frames)
 *   image.pgm         the stitched image, also for rejected swipes when one was stitched
 *
 * The data is a fingerprint: DIR is root-only (0700, files 0600), the oldest swipes are
 * deleted beyond VFS495_DIAG_MAX_SWIPES, and recording stops by itself at the "until" time.
 */
#pragma once

#include <gio/gio.h>

#include "vfs495-assemble.h"
#include "vfs495-image.h"

#define VFS495_DIAG_DIR         "/var/lib/vfs495-driver/diag"   /* or $VFS495_DIAG_DIR */
#define VFS495_DIAG_MAX_SWIPES  500                             /* about 0.5 MB each */
#define VFS495_DIAG_MAX_EVENTS  (8 * 1024 * 1024)               /* then events.log -> .1 */

typedef struct _Vfs495Diag Vfs495Diag;

/* NULL when diagnostics are off */
Vfs495Diag *vfs495_diag_open  (void);
Vfs495Diag *vfs495_diag_ref   (Vfs495Diag *diag);
void        vfs495_diag_unref (Vfs495Diag *diag);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (Vfs495Diag, vfs495_diag_unref)

void vfs495_diag_event (Vfs495Diag *diag,
                        const char *format,
                        ...) G_GNUC_PRINTF (2, 3);

typedef struct
{
  const char         *action;        /* enroll, verify, identify, capture */
  const char         *verdict;
  const char         *error;         /* the stitcher's message, or NULL */
  int                 lines;
  Vfs495DecodeInfo    decoded;
  Vfs495AssembleInfo  info;
  /* milliseconds */
  double              setup_ms;      /* sensor setup before this arming, 0 if none */
  double              wait_ms;       /* arming to first data */
  double              swipe_ms;      /* first data to the end of the stream */
  double              decode_ms;
  double              assemble_ms;
  guint               stream_bytes;
  guint               after_abort;   /* bytes the sensor pushed after the abort */
  guint16             abort_status;
  gboolean            port_reset;    /* the setup reset the USB port */
  gboolean            recovering;    /* the capture followed an error */
} Vfs495DiagSwipe;

/* thread-safe; plain and image may be NULL */
void vfs495_diag_swipe (Vfs495Diag            *diag,
                        const Vfs495DiagSwipe *swipe,
                        const guint8          *plain,
                        gsize                  plain_len,
                        const guint8          *image,
                        int                    rows);
