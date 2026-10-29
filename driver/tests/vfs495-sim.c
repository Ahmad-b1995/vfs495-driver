#include "vfs495-sim.h"

#include <math.h>
#include <openssl/evp.h>
#include <string.h>

#define RIDGE_PERIOD  9.0     /* pixels, about 0.45 mm at the sensor's resolution */
#define FRAME         272
#define HEADER        8

static double
gauss (GRand *r)
{
  double u = g_rand_double_range (r, 1e-12, 1.0), v = g_rand_double (r);

  return sqrt (-2.0 * log (u)) * cos (2 * G_PI * v);
}

/* smooth random field: a sum of waves with wavelengths from min_wl to max_wl pixels */
typedef struct
{
  double a[12], fx[12], fy[12], p[12];
} Waves;

static void
waves_init (Waves *w, GRand *r, double amplitude, double min_wl, double max_wl)
{
  for (int k = 0; k < 12; k++)
    {
      double wl = g_rand_double_range (r, min_wl, max_wl), angle = g_rand_double_range (r, 0, G_PI);

      w->a[k] = amplitude * g_rand_double_range (r, 0.5, 1.0) / sqrt (12);
      w->fx[k] = 2 * G_PI / wl * cos (angle);
      w->fy[k] = 2 * G_PI / wl * sin (angle);
      w->p[k] = g_rand_double_range (r, 0, 2 * G_PI);
    }
}

static double
waves_at (const Waves *w, double x, double y)
{
  double v = 0;

  for (int k = 0; k < 12; k++)
    v += w->a[k] * sin (w->fx[k] * x + w->fy[k] * y + w->p[k]);
  return v;
}

SimFinger *
sim_finger_new (guint32 seed, int height)
{
  g_autoptr(GRand) r = g_rand_new_with_seed (seed);
  SimFinger *f = g_new0 (SimFinger, 1);
  double cx = 100 + g_rand_double_range (r, -15, 15), cy = height * g_rand_double_range (r, 0.4, 0.55);
  Waves bend, spacing, depth;

  /* real ridges are not evenly spaced: they bend, widen and narrow, and fade in places */
  waves_init (&bend, r, 6.0, 40, 160);
  waves_init (&spacing, r, 0.12, 60, 240);
  waves_init (&depth, r, 0.35, 15, 60);
  f->height = height;
  f->ridges = g_new (guint8, (gsize) SIM_FINGER_WIDTH * height);
  f->contact = g_new (float, (gsize) SIM_FINGER_WIDTH * height);
  for (int y = 0; y < height; y++)
    for (int x = 0; x < SIM_FINGER_WIDTH; x++)
      {
        /* a whorl around (cx, cy) */
        double d = hypot (x - cx, (y - cy) * 0.8) + waves_at (&bend, x, y);
        double period = RIDGE_PERIOD * (1 + waves_at (&spacing, x, y));
        double contrast = CLAMP (1 + waves_at (&depth, x, y), 0.2, 1.0), e;
        gsize i = (gsize) y * SIM_FINGER_WIDTH + x;

        f->ridges[i] = (guint8) lround (127.5 + 127.5 * contrast * cos (2 * G_PI * d / period));
        /* the fingertip pressed flat: a rounded rectangle wider than the sensor */
        e = pow ((x - 100) / 150.0, 4) + pow ((y - height / 2.0) / (height / 2.0), 4);
        f->contact[i] = (float) CLAMP ((1.0 - e) * 4.0, 0.0, 1.0);
      }
  return f;
}

void
sim_finger_free (SimFinger *f)
{
  if (!f)
    return;
  g_free (f->ridges);
  g_free (f->contact);
  g_free (f);
}

SimSwipe
sim_swipe_default (void)
{
  return (SimSwipe) {
    .seed = 1,
    .speed_start = 0.3,
    .speed_end = 0.3,
    .start_row = 20,
    .travel = 560,
    .rest_lines = 0,
    .tail_lines = 1200,
    .left = 0,
    .right = VFS495_MAIN_WIDTH,
    .dead_column = -1,
    .noise = 4.0,
  };
}

/* the sensor's reading at finger position (column x, row y): ridge levels under the finger,
 * the column's own level without one */
static double
sense (const SimFinger *f, const SimSwipe *s, int x, double y, double base)
{
  int y0 = (int) floor (y);
  double fy = y - y0, ridge = 0, contact = 0;

  if (x < s->left || x >= s->right || y0 < 0 || y0 + 1 >= f->height)
    return base;
  for (int k = 0; k < 2; k++)
    {
      gsize i = (gsize) (y0 + k) * SIM_FINGER_WIDTH + x;
      double w = k ? fy : 1 - fy;

      ridge += w * f->ridges[i];
      contact += w * f->contact[i];
    }
  return base + contact * (127 + 0.55 * (ridge - 127.5) - base);
}

static guint8
pixel (double v)
{
  return (guint8) CLAMP (lround (v), 0, 255);
}

guint8 *
sim_swipe_lines (const SimFinger *f, const SimSwipe *s, int *n_lines)
{
  g_autoptr(GRand) r = g_rand_new_with_seed (s->seed);
  g_autoptr(GByteArray) out = g_byte_array_new ();
  double base[VFS495_LINE_WIDTH];
  const double y0 = s->start_row;
  double y = y0;
  int tail = 0;

  for (int c = 0; c < VFS495_LINE_WIDTH; c++)
    base[c] = 122 + 8 * gauss (r);
  for (int t = 0;; t++)
    {
      guint8 line[VFS495_LINE_WIDTH];
      gboolean gone = y - y0 >= s->travel;

      if (gone && tail++ >= s->tail_lines)
        break;
      for (int c = 0; c < VFS495_MAIN_WIDTH; c++)
        line[c] = c == s->dead_column ? 0 : pixel (gone ? base[c] + s->noise * gauss (r) :
                                                   sense (f, s, c, y, base[c]) + s->noise * gauss (r));
      for (int k = 0; k < VFS495_LINE_WIDTH - VFS495_MAIN_WIDTH; k++)
        {
          int c = VFS495_MAIN_WIDTH + k;
          double v = gone ? base[c] : sense (f, s, SIM_AUX_OVER + k, y + SIM_LINE_DISTANCE, base[c]);

          line[c] = pixel (255 - v + s->noise * gauss (r));
        }
      g_byte_array_append (out, line, VFS495_LINE_WIDTH);
      if (t >= s->rest_lines && !gone)
        {
          double p = (y - y0) / s->travel;

          y += s->speed_start + p * (s->speed_end - s->speed_start);
        }
    }
  *n_lines = (int) (out->len / VFS495_LINE_WIDTH);
  return g_byte_array_free (g_steal_pointer (&out), FALSE);
}

void
sim_descramble_table (guint16 t[VFS495_LINE_WIDTH])
{
  for (int i = 0; i < 200; i++)
    t[i] = (guint16) (199 - i);
  for (int i = 200; i < 242; i++)
    t[i] = (guint16) (262 - (i - 200));
  t[242] = 263;
  for (int i = 243; i < 264; i++)
    t[i] = (guint16) (220 - (i - 243));
}

GByteArray *
sim_frames (const guint8 *lines, int n_lines, const guint16 *descramble, const int *drop, int n_drop)
{
  GByteArray *out = g_byte_array_new ();
  guint8 frame[FRAME];

  for (int t = 0; t < n_lines; t++)
    {
      gboolean dropped = FALSE;

      for (int k = 0; k < n_drop; k++)
        dropped |= drop[k] == t;
      if (dropped)
        continue;
      memset (frame, 0, HEADER);
      frame[0] = 0x01;
      frame[1] = 0xfe;
      frame[2] = (guint8) t;
      frame[3] = (guint8) (t >> 8);
      for (int k = 0; k < VFS495_LINE_WIDTH; k++)
        frame[HEADER + k] = lines[(gsize) t * VFS495_LINE_WIDTH + descramble[k]];
      g_byte_array_append (out, frame, FRAME);
    }
  /* the status frame that ends every recorded stream */
  memset (frame, 0, FRAME);
  frame[0] = 0x01;
  frame[1] = 0x01;
  frame[3] = 0x14;
  g_byte_array_append (out, frame, FRAME);
  return out;
}

GByteArray *
sim_encrypt (const GByteArray *plain, const guint8 key[32], const guint8 iv[16])
{
  GByteArray *out = g_byte_array_sized_new (plain->len);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
  int n = 0;

  g_assert (plain->len % 16 == 0);
  g_byte_array_set_size (out, plain->len);
  g_assert (EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv));
  EVP_CIPHER_CTX_set_padding (ctx, 0);
  g_assert (EVP_EncryptUpdate (ctx, out->data, &n, plain->data, (int) plain->len) && n == (int) plain->len);
  EVP_CIPHER_CTX_free (ctx);
  return out;
}

/* normalised cross-correlation of image rows r0..r0+n-1 with finger rows from y0 on */
static double
ncc (const SimFinger *f, const guint8 *image, int r0, int n, int y0)
{
  double sa = 0, sb = 0, saa = 0, sbb = 0, sab = 0, cov, va, vb;
  int count = 0;

  for (int r = 0; r < n; r++)
    for (int x = 10; x < SIM_FINGER_WIDTH - 10; x++)
      {
        gsize i = (gsize) (y0 + r) * SIM_FINGER_WIDTH + x;
        double a = image[(gsize) (r0 + r) * VFS495_MAIN_WIDTH + x], b = f->ridges[i];

        if (f->contact[i] < 0.5)
          continue;
        sa += a;
        sb += b;
        saa += a * a;
        sbb += b * b;
        sab += a * b;
        count++;
      }
  if (count < n * (SIM_FINGER_WIDTH - 20) / 2)
    return -1;
  cov = sab - sa * sb / count;
  va = saa - sa * sa / count;
  vb = sbb - sb * sb / count;
  return cov / (sqrt (va * vb) + 1e-9);
}

SimMatch
sim_match (const SimFinger *f, const guint8 *image, int rows)
{
  const int block = 48;
  double sum = 0, sx = 0, sy = 0, sxx = 0, sxy = 0;
  int blocks = 0;
  SimMatch m = { -1, 0 };

  for (int r0 = 0; r0 + block <= rows; r0 += block)
    {
      double best = -1;
      int at = 0;

      for (int y0 = 0; y0 + block <= f->height; y0++)
        {
          double c = ncc (f, image, r0, block, y0);

          if (c > best)
            {
              best = c;
              at = y0;
            }
        }
      if (best < 0)
        continue;
      sum += best;
      sx += r0;
      sy += at;
      sxx += (double) r0 * r0;
      sxy += (double) r0 * at;
      blocks++;
    }
  if (blocks < 2)
    return m;
  m.correlation = sum / blocks;
  m.scale = (blocks * sxy - sx * sy) / (blocks * sxx - sx * sx);
  return m;
}
