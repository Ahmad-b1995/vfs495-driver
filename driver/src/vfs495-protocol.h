/*
 * VFS495 protocol without I/O: constants, the Validity SSLv3 record layer and the handshake
 * steps. Shared by the blocking test session (vfs495-proto.c) and the libfprint driver.
 */
#pragma once

#include <gio/gio.h>

#define VFS495_EP_OUT            0x01
#define VFS495_EP_CMD_IN         0x81
#define VFS495_EP_DATA_IN        0x82
#define VFS495_REPLY_MAX         16384
#define VFS495_DATA_CHUNK        16384

#define VFS495_CMD_ABORT         0x04
#define VFS495_CMD_FINGER_STATE  0x17
#define VFS495_CMD_FLASH_READ    0x1f

#define VFS495_FLASH_BLOCK_LEN   4096   /* the pre-session flash block holding the RSA key */
#define VFS495_FLASH_KEY_OFFSET  1718
#define VFS495_RSA_LEN           256

/*
 * After a flash read (0x1f) the sensor resets itself if the next command follows at once;
 * 1 ms was enough in tests. HP's tool never waits less than 12 ms (128-byte read) or 20 ms
 * (4096-byte read), so wait as long as HP does.
 */
#define VFS495_FLASH_SETTLE_MS   20

#define VFS495_POLL_INTERVAL_MS  50    /* HP polls finger state about every 50 ms; the driver does
                                          not poll (README, finding 22) */
/*
 * A swipe has ended when the data endpoint stays quiet. Inside 19 measured swipes the longest
 * pause was 4 ms (HP's recordings: 21 ms), but one early test swipe paused after its first
 * 3 frames and continued within 200 ms, so the first frames get a longer window.
 */
#define VFS495_SWIPE_QUIET_START_MS  300
#define VFS495_SWIPE_QUIET_MS        80
#define VFS495_SWIPE_START_BYTES     (50 * 272)
#define VFS495_SWIPE_LIMIT_MS    10000

/*
 * Swipe streams have no length header and may end on a 64-byte packet boundary with no
 * short packet, and GUsb drops the byte count of a transfer that times out or is cancelled.
 * So reads on the data endpoint never time out: a queue of them stays pending from arming
 * until after the abort, as HP's tool keeps one pending. Each read is 1088 bytes, the least
 * common multiple of the packet size (64) and the frame size (272). Streams are whole
 * frames, so every read either fills or ends on a short packet, and no read can hold part of
 * a stream when the stream stops.
 */
#define VFS495_READ_LEN          1088
#define VFS495_READ_QUEUE        4

typedef struct
{
  guint8  mac_key[20];
  guint8  key[32];
  guint8  iv[16];
  guint64 seq;
} Vfs495Direction;

typedef struct
{
  Vfs495Direction client;
  Vfs495Direction server;

  /* handshake state, cleared once the session is up */
  guint8          client_random[32];
  guint8          premaster[48];
  GByteArray     *hello;        /* ClientHello handshake message, for the Finished hash */
} Vfs495Crypto;

/* forget all keys */
void        vfs495_crypto_clear (Vfs495Crypto *c);

/* step 1: the ClientHello message (command 0x11) from the recorded template */
GByteArray *vfs495_crypto_hello (Vfs495Crypto *c,
                                 GBytes       *hello_template,
                                 GError      **error);

/* step 2: from the ServerHello and the sensor's RSA key (from its flash), derive the session
 * keys and build the key exchange, ChangeCipherSpec and Finished message (command 0x11) */
GByteArray *vfs495_crypto_key_exchange (Vfs495Crypto *c,
                                        const guint8 *server_hello,
                                        gsize         len,
                                        const guint8  modulus_le[VFS495_RSA_LEN],
                                        GError      **error);

/* the key derivation and Finished computation of step 2, for tests against recorded sessions */
void        vfs495_crypto_derive (Vfs495Crypto *c,
                                  const guint8  premaster[48],
                                  const guint8  client_random[32],
                                  const guint8  server_random[32],
                                  guint8        master_out[48],
                                  guint8        keyblock_out[136]);
void        vfs495_crypto_finished (const guint8  master[48],
                                    const guint8 *handshake,
                                    gsize         len,
                                    guint8        out[36]);

/* step 3: check the sensor's reply: ChangeCipherSpec, its Finished and one unsolicited
 * record, which must be decrypted to keep the IV and sequence number in step */
gboolean    vfs495_crypto_finish (Vfs495Crypto *c,
                                  const guint8 *reply,
                                  gsize         len,
                                  GError      **error);

/* an encrypted record (application data 0x17, alert 0x15) */
GByteArray *vfs495_crypto_seal (Vfs495Crypto *c,
                                guint8        type,
                                const guint8 *data,
                                gsize         len);

/* decrypt and MAC-check every record of a reply */
GByteArray *vfs495_crypto_open (Vfs495Crypto *c,
                                const guint8 *reply,
                                gsize         len,
                                GError      **error);

/*
 * The bytes to send for a signed patch. The command file holds it as LABEL[8] followed by the
 * patch command as HP ships it (06 | 02 00 | 00 01 | RSA signature[256] | body). LABEL (u32
 * patch id, u8 version, "PS", ff) names the HMAC the sensor's firmware verified once and
 * HP's software cached in the sensor's flash (40-byte entries: label, HMAC). With the entry in
 * the pre-session flash block, the patch is sent as HP's tool sends it (06 | 02 00 | 20 00 |
 * HMAC[32] | body); without it, with the RSA signature, which the sensor also accepts.
 */
guint8     *vfs495_patch_for_sensor (const guint8 *payload,
                                     gsize         len,
                                     const guint8 *flash,
                                     gsize         flash_len,
                                     gsize        *out_len,
                                     GError      **error);

/* the arming command's key field: bytes 0-31 image key, 32-47 IV, 48-95 random (HP sends
 * fresh random data there every time; the sensor does not check it) */
#define VFS495_KEY_FIELD_LEN     96

/* replies start with a u16 status; 0 is success */
gboolean    vfs495_check_status (const guint8 *reply,
                                 gsize         len,
                                 guint8        cmd,
                                 GError      **error);

/* the first max bytes as hex, for debug logs (the 0x01 reply carries the sensor's state) */
char       *vfs495_hex_prefix (const guint8 *data,
                               gsize         len,
                               gsize         max);
