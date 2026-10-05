/* the stitcher (vfs495_assemble, vfs495_swipe_verdict) on arbitrary scan lines */
#include "fuzz.h"
#include "vfs495-assemble.h"

#define MAX_LINES 400    /* the stitcher's code paths are the same at any length */

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  int n = (int) MIN (size / VFS495_LINE_WIDTH, MAX_LINES);
  Vfs495AssembleInfo info;
  g_autofree guint8 *img = vfs495_assemble (data, n, &info, NULL);

  vfs495_swipe_verdict (img, &info);
  if (img)
    g_assert (info.rows > 0 && info.first_line >= 0 && info.last_line <= n && info.first_line < info.last_line);
  return 0;
}
