/* Replays saved fuzz inputs through a target: run-corpus FILE|DIR... (exit 77 if none). */
#include <stdio.h>

#include "fuzz.h"

static int
run_file (const char *path)
{
  g_autofree char *data = NULL;
  gsize len;

  if (!g_file_get_contents (path, &data, &len, NULL))
    return 0;
  LLVMFuzzerTestOneInput ((const uint8_t *) data, len);
  return 1;
}

int
main (int argc, char **argv)
{
  int n = 0;

  for (int i = 1; i < argc; i++)
    {
      g_autoptr(GDir) dir = g_dir_open (argv[i], 0, NULL);
      const char *name;

      if (!dir)
        {
          n += run_file (argv[i]);
          continue;
        }
      while ((name = g_dir_read_name (dir)))
        {
          g_autofree char *path = g_build_filename (argv[i], name, NULL);
          n += run_file (path);
        }
    }
  printf ("%d inputs replayed\n", n);
  return n ? 0 : 77;
}
