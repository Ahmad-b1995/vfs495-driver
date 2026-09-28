/*
 * VFS495 sensor protocol: command data file, plaintext setup, the Validity SSLv3 session,
 * encrypted commands, finger detection and capture. Blocking; the swipe wait iterates the
 * default main context to deliver its pending data reads. A test bed for the libfprint driver,
 * which runs the same sequence asynchronously. Mirrors research/session/vfs495.py and capture.py.
 */
#pragma once

#include <gio/gio.h>
#include <gusb.h>

#include "vfs495-assemble.h"

#include "vfs495-commands.h"

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
 * Poll until the sensor streams a swipe, collect the stream until it stays quiet for 300 ms,
 * then abort. Returns TRUE with *stream set (empty if the sensor saw no finger) and decrypts
 * nothing.
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

/* restore the sensor's pre-session state and end the session (close_notify); errors are ignored */
void vfs495_session_close (Vfs495Session *s);
