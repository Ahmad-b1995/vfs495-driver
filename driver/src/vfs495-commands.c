#include "vfs495-commands.h"

#include <string.h>

static void
command_free (gpointer p)
{
  Vfs495Command *c = p;

  g_bytes_unref (c->payload);
  g_free (c);
}

Vfs495Commands *
vfs495_commands_load (const char *path, GError **error)
{
  g_autofree char *data = NULL;
  gsize len, pos = 12;
  guint32 count;
  gboolean have_table = FALSE;
  Vfs495Commands *cmds;

  if (!g_file_get_contents (path, &data, &len, error))
    return NULL;
  if (len < 12 || memcmp (data, "VFS495C2", 8) != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "%s: not a VFS495 command file", path);
      return NULL;
    }
  count = GUINT32_FROM_LE (*(guint32 *) (data + 8));
  cmds = g_new0 (Vfs495Commands, 1);
  cmds->commands = g_ptr_array_new_with_free_func (command_free);
  for (guint32 i = 0; i < count; i++)
    {
      Vfs495Command *c;
      guint32 n;

      if (pos + 12 > len)
        goto truncated;
      n = GUINT32_FROM_LE (*(guint32 *) (data + pos + 8));
      if (pos + 12 + n > len)
        goto truncated;
      c = g_new0 (Vfs495Command, 1);
      c->phase = (guint8) data[pos];
      c->key_offset = GUINT16_FROM_LE (*(guint16 *) (data + pos + 2));
      c->data_len = GUINT32_FROM_LE (*(guint32 *) (data + pos + 4));
      c->payload = g_bytes_new (data + pos + 12, n);
      pos += 12 + n;
      if (c->phase == VFS495_PHASE_DESCRAMBLE && n == sizeof cmds->descramble)
        {
          for (int k = 0; k < VFS495_LINE_WIDTH; k++)
            cmds->descramble[k] = GUINT16_FROM_LE (((guint16 *) (data + pos - n))[k]);
          have_table = TRUE;
          command_free (c);
          continue;
        }
      g_ptr_array_add (cmds->commands, c);
    }
  if (!have_table)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "%s: no descramble table", path);
      vfs495_commands_free (cmds);
      return NULL;
    }
  return cmds;

truncated:
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "%s: truncated", path);
  vfs495_commands_free (cmds);
  return NULL;
}

void
vfs495_commands_free (Vfs495Commands *cmds)
{
  if (!cmds)
    return;
  g_ptr_array_unref (cmds->commands);
  g_free (cmds);
}
