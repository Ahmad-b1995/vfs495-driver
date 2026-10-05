#include "vfs495-commands.h"

#include <string.h>

#define HEADER_LEN 12   /* magic, u32 count */
#define ENTRY_LEN  12   /* u8 phase, u8 flags, u16 key offset, u32 data length, u32 length */

static void
command_free (gpointer p)
{
  Vfs495Command *c = p;

  g_bytes_unref (c->payload);
  g_free (c);
}

/* little-endian reads that are valid at any alignment */
static guint16
le16 (const guint8 *p)
{
  return (guint16) (p[0] | p[1] << 8);
}

static guint32
le32 (const guint8 *p)
{
  return (guint32) p[0] | (guint32) p[1] << 8 | (guint32) p[2] << 16 | (guint32) p[3] << 24;
}

/* The decoder writes pixel i of a line to column descramble[i], so the table must be a
 * permutation of the line's columns. */
static gboolean
read_descramble (const guint8 *p, guint16 table[VFS495_LINE_WIDTH])
{
  gboolean seen[VFS495_LINE_WIDTH] = { FALSE };

  for (int k = 0; k < VFS495_LINE_WIDTH; k++)
    {
      guint16 v = le16 (p + 2 * k);

      if (v >= VFS495_LINE_WIDTH || seen[v])
        return FALSE;
      seen[v] = TRUE;
      table[k] = v;
    }
  return TRUE;
}

Vfs495Commands *
vfs495_commands_parse (const guint8 *data, gsize len, const char *name, GError **error)
{
  gsize pos = HEADER_LEN;
  guint32 count;
  gboolean have_table = FALSE;
  Vfs495Commands *cmds;

  if (len < HEADER_LEN || memcmp (data, "VFS495C2", 8) != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "%s: not a VFS495 command file", name);
      return NULL;
    }
  count = le32 (data + 8);
  cmds = g_new0 (Vfs495Commands, 1);
  cmds->commands = g_ptr_array_new_with_free_func (command_free);
  for (guint32 i = 0; i < count; i++)
    {
      const guint8 *e = data + pos;
      Vfs495Command *c;
      guint32 n;

      if (len - pos < ENTRY_LEN)
        goto bad;
      n = le32 (e + 8);
      if (len - pos - ENTRY_LEN < n || e[0] > VFS495_PHASE_CLOSE)
        goto bad;
      pos += ENTRY_LEN + n;
      if (e[0] == VFS495_PHASE_DESCRAMBLE)
        {
          if (n != 2 * VFS495_LINE_WIDTH || !read_descramble (e + ENTRY_LEN, cmds->descramble))
            goto bad;
          have_table = TRUE;
          continue;
        }
      c = g_new0 (Vfs495Command, 1);
      c->phase = e[0];
      c->flags = e[1];
      c->key_offset = le16 (e + 2);
      c->data_len = le32 (e + 4);
      c->payload = g_bytes_new (e + ENTRY_LEN, n);
      g_ptr_array_add (cmds->commands, c);
    }
  if (!have_table)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "%s: no descramble table", name);
      vfs495_commands_free (cmds);
      return NULL;
    }
  return cmds;

bad:
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "%s: malformed entry at offset %zu", name, pos);
  vfs495_commands_free (cmds);
  return NULL;
}

Vfs495Commands *
vfs495_commands_load (const char *path, GError **error)
{
  g_autofree char *data = NULL;
  gsize len;

  if (!g_file_get_contents (path, &data, &len, error))
    return NULL;
  return vfs495_commands_parse ((const guint8 *) data, len, path, error);
}

void
vfs495_commands_free (Vfs495Commands *cmds)
{
  if (!cmds)
    return;
  g_ptr_array_unref (cmds->commands);
  g_free (cmds);
}
