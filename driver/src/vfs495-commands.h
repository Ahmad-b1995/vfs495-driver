/*
 * The command data file: the sensor's setup and capture commands in order, with the data
 * length the sensor sends after each and the column descramble table. Generated from a
 * decrypted recording by driver/tools/make-commands.py (format described there).
 */
#pragma once

#include <gio/gio.h>

#include "vfs495-assemble.h"

#define VFS495_NO_KEY 0xFFFF

typedef enum {
  VFS495_PHASE_PRE = 0,     /* plaintext commands before the session */
  VFS495_PHASE_HELLO,       /* ClientHello template */
  VFS495_PHASE_SETUP,       /* configuration after the handshake */
  VFS495_PHASE_REARM,       /* commands that prepare the next capture after an abort */
  VFS495_PHASE_ARM,         /* arms finger detection; carries the image key */
  VFS495_PHASE_DESCRAMBLE,  /* column descramble table */
  VFS495_PHASE_CLOSE,       /* restores the pre-session patch before close_notify */
} Vfs495Phase;

typedef struct
{
  Vfs495Phase phase;
  guint32     data_len;     /* bytes the sensor sends on endpoint 0x82 after this command */
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
