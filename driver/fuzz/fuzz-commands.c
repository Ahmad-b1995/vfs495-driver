/* the command file parser (vfs495_commands_parse) */
#include "fuzz.h"
#include "vfs495-commands.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Vfs495Commands *cmds = vfs495_commands_parse (data, size, "fuzz", NULL);

  if (cmds)
    {
      /* what the driver reads from each command */
      for (guint i = 0; i < cmds->commands->len; i++)
        {
          const Vfs495Command *c = g_ptr_array_index (cmds->commands, i);
          gsize len;
          const guint8 *p = g_bytes_get_data (c->payload, &len);
          volatile guint8 sink = len ? p[0] ^ p[len - 1] : 0;
          (void) sink;
        }
      for (int k = 0; k < VFS495_LINE_WIDTH; k++)
        g_assert (cmds->descramble[k] < VFS495_LINE_WIDTH);
    }
  vfs495_commands_free (cmds);
  return 0;
}
