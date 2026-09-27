/*
 * VFS495 sensor protocol: command data file, plaintext setup, the Validity SSLv3 session,
 * encrypted commands, finger detection and capture. Synchronous; meant for a worker thread.
 * Mirrors research/session/vfs495.py and capture.py.
 */
#pragma once

#include <gio/gio.h>
#include <gusb.h>

#include "vfs495-assemble.h"

typedef enum {
  VFS495_PHASE_PRE = 0,     /* plaintext commands before the session */
  VFS495_PHASE_HELLO,       /* ClientHello template */
  VFS495_PHASE_SETUP,       /* configuration after the handshake */
  VFS495_PHASE_REARM,       /* commands that prepare the next capture after an abort */
  VFS495_PHASE_ARM,         /* arms finger detection; carries the image key */
  VFS495_PHASE_DESCRAMBLE,  /* column descramble table */
} Vfs495Phase;

typedef struct
{
  Vfs495Phase phase;
  gboolean    sends_data;   /* the sensor sends data on endpoint 0x82 after this command */
  guint16     key_offset;   /* offset of the 64-byte image-key field, 0xFFFF if none */
  GBytes     *payload;
} Vfs495Command;

typedef struct
{
  GPtrArray *commands;      /* Vfs495Command, in file order */
  guint16    descramble[VFS495_LINE_WIDTH];
} Vfs495Commands;

Vfs495Commands *vfs495_commands_load (const char *path,
                                      GError    **error);
void            vfs495_commands_free (Vfs495Commands *cmds);

typedef struct _Vfs495Session Vfs495Session;

/* usb must be open with interface 0 claimed; the session does not take ownership */
Vfs495Session *vfs495_session_new (GUsbDevice           *usb,
                                   const Vfs495Commands *cmds);
void           vfs495_session_free (Vfs495Session *s);

/* plaintext setup, handshake (key read from the sensor's flash) and configuration */
gboolean vfs495_session_open (Vfs495Session *s,
                              GError       **error);

/* arm finger detection with a fresh image key; re-arms first if a capture ran before */
gboolean vfs495_session_arm (Vfs495Session *s,
                             GError       **error);

/*
 * Poll until the sensor streams a swipe, collect the stream, then abort. Returns TRUE with
 * *stream set (may be empty if cancelled or timed out; check the error) and decrypts nothing.
 * On cancellation returns FALSE with G_IO_ERROR_CANCELLED after aborting cleanly.
 */
gboolean vfs495_session_wait_swipe (Vfs495Session *s,
                                    GCancellable  *cancellable,
                                    GByteArray   **stream,
                                    GError       **error);

/* key and IV of the current arming, for decrypting the stream */
void vfs495_session_image_key (Vfs495Session *s,
                               guint8         key[32],
                               guint8         iv[16]);

/* end the session politely (close_notify); errors are ignored */
void vfs495_session_close (Vfs495Session *s);
