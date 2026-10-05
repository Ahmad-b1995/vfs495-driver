/* the swipe frame parser (vfs495_frames_to_lines), on decrypted stream bytes */
#include "fuzz.h"
#include "vfs495-image.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  guint16 descramble[VFS495_LINE_WIDTH];
  Vfs495DecodeInfo info;
  int n = 0;

  for (int k = 0; k < VFS495_LINE_WIDTH; k++)
    descramble[k] = (guint16) (VFS495_LINE_WIDTH - 1 - k);
  g_free (vfs495_frames_to_lines (data, size, descramble, &n, &info));
  g_assert (n >= 0 && info.frames == (guint) n);
  return 0;
}
