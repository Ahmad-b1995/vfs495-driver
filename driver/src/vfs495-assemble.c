/*
 * VFS495 swipe assembly. Ports research/quality/assemble.py; the filters reproduce SciPy's
 * defaults (uniform_filter1d / gaussian_filter1d in "reflect" mode, median_filter in
 * "nearest" mode) so results can be compared with the Python version.
 */
#include "vfs495-assemble.h"

#include <math.h>
#include <string.h>

#define AUX_START          200
#define AUX_WIDTH          64
#define C0_FIRST           58
#define C0_LAST            79          /* inclusive: aux over main columns c0 .. c0 + 63 */
#define MAX_LAG            250
#define WINDOW             24          /* lines per lag-correlation window */
#define MIN_TRUSTED_LAG    8           /* shorter: crosstalk between the two lines */
#define MAX_TRUSTED_LAG    245         /* longer: edge of the search range */
#define RUN_GAP            120         /* trusted readings closer than this are one swipe */
#define CONF_MIN           0.3
#define LINE_DISTANCE      8.0         /* aux-to-main distance in pixels, calibrated */
#define STILL_LAG          20          /* a resting finger repeats the line this many earlier */
#define STILL_THRESHOLD    0.8
#define HIGHPASS_BOX       9
#define ENERGY_SIGMA       15.0
#define EPS                1e-6

/* ---- SciPy-compatible 1-D filters ------------------------------------------------------ */

/* index into [0, n) with SciPy "reflect" (half-sample symmetric) boundaries */
static int
reflect (int i, int n)
{
  if (n == 1)
    return 0;
  while (i < 0 || i >= n)
    {
      if (i < 0)
        i = -i - 1;
      if (i >= n)
        i = 2 * n - i - 1;
    }
  return i;
}

/* uniform_filter1d(x, size) with origin 0: window [i - size/2, i + size - 1 - size/2] */
static void
box_filter (const double *x, double *out, int n, int size)
{
  int left = size / 2;
  int right = size - 1 - left;

  for (int i = 0; i < n; i++)
    {
      double s = 0;
      for (int k = -left; k <= right; k++)
        s += x[reflect (i + k, n)];
      out[i] = s / size;
    }
}

/* box_filter, computing only out[lo..hi-1], with running sums over a reflected copy */
static void
box_filter_range (const double *x, double *out, int n, int size, int lo, int hi)
{
  int left = size / 2;
  int right = size - 1 - left;
  int len = hi - lo + size;
  g_autofree double *prefix = g_new (double, len + 1);

  prefix[0] = 0;
  for (int j = 0; j < len; j++)
    prefix[j + 1] = prefix[j] + x[reflect (lo - left + j, n)];
  for (int i = lo; i < hi; i++)
    out[i] = (prefix[i - lo + left + right + 1] - prefix[i - lo]) / size;
}

static void
gaussian_filter (const double *x, double *out, int n, double sigma)
{
  int radius = (int) (4.0 * sigma + 0.5);
  g_autofree double *w = g_new (double, 2 * radius + 1);
  double sum = 0;

  for (int k = -radius; k <= radius; k++)
    sum += w[k + radius] = exp (-0.5 * k * k / (sigma * sigma));
  for (int i = 0; i < n; i++)
    {
      double s = 0;
      for (int k = -radius; k <= radius; k++)
        s += w[k + radius] * x[reflect (i + k, n)];
      out[i] = s / sum;
    }
}

static int
cmp_double (const void *a, const void *b)
{
  double x = *(const double *) a, y = *(const double *) b;

  return (x > y) - (x < y);
}

/* numpy.median */
static double
median (const double *x, int n)
{
  g_autofree double *s = g_memdup2 (x, n * sizeof (double));

  qsort (s, n, sizeof (double), cmp_double);
  return n % 2 ? s[n / 2] : 0.5 * (s[n / 2 - 1] + s[n / 2]);
}

/* numpy.percentile, linear interpolation */
static double
percentile (const double *x, int n, double q)
{
  g_autofree double *s = g_memdup2 (x, n * sizeof (double));
  double pos = q / 100.0 * (n - 1);
  int lo = (int) floor (pos);
  int hi = MIN (lo + 1, n - 1);

  qsort (s, n, sizeof (double), cmp_double);
  return s[lo] + (s[hi] - s[lo]) * (pos - lo);
}

/* median_filter(x, size) with "nearest" boundaries */
static void
median_filter (const double *x, double *out, int n, int size)
{
  g_autofree double *win = g_new (double, size);
  int half = size / 2;

  for (int i = 0; i < n; i++)
    {
      for (int k = -half; k < size - half; k++)
        win[k + half] = x[CLAMP (i + k, 0, n - 1)];
      qsort (win, size, sizeof (double), cmp_double);
      out[i] = win[half];
    }
}

/* numpy.interp for sorted xp, holding the end values outside */
static double
interp (double x, const double *xp, const double *fp, int n)
{
  int lo = 0, hi = n - 1;

  if (x <= xp[0])
    return fp[0];
  if (x >= xp[n - 1])
    return fp[n - 1];
  while (hi - lo > 1)
    {
      int mid = (lo + hi) / 2;
      if (xp[mid] <= x)
        lo = mid;
      else
        hi = mid;
    }
  return fp[lo] + (fp[hi] - fp[lo]) * (x - xp[lo]) / (xp[hi] - xp[lo]);
}

/* ---- image helpers (row-major, n rows x w columns, double) ----------------------------- */

/* x - column mean, then minus a HIGHPASS_BOX-wide horizontal moving average */
static double *
highpass (const double *x, int n, int w)
{
  double *out = g_new (double, (gsize) n * w);
  g_autofree double *mean = g_new0 (double, w);
  g_autofree double *row = g_new (double, w);
  g_autofree double *smooth = g_new (double, w);

  for (int r = 0; r < n; r++)
    for (int c = 0; c < w; c++)
      mean[c] += x[(gsize) r * w + c];
  for (int c = 0; c < w; c++)
    mean[c] /= n;
  for (int r = 0; r < n; r++)
    {
      for (int c = 0; c < w; c++)
        row[c] = x[(gsize) r * w + c] - mean[c];
      box_filter (row, smooth, w, HIGHPASS_BOX);
      for (int c = 0; c < w; c++)
        out[(gsize) r * w + c] = row[c] - smooth[c];
    }
  return out;
}

/* each row minus its mean, scaled to unit length */
static void
unit_row (const double *x, double *out, int w)
{
  double mean = 0, norm = 0;

  for (int c = 0; c < w; c++)
    mean += x[c];
  mean /= w;
  for (int c = 0; c < w; c++)
    {
      out[c] = x[c] - mean;
      norm += out[c] * out[c];
    }
  norm = sqrt (norm) + EPS;
  for (int c = 0; c < w; c++)
    out[c] /= norm;
}

static double *
column (const double *x, int n, int w, int c)
{
  double *col = g_new (double, n);

  for (int r = 0; r < n; r++)
    col[r] = x[(gsize) r * w + c];
  return col;
}

static double
stddev (const double *x, int n)
{
  double m = 0, v = 0;

  for (int i = 0; i < n; i++)
    m += x[i];
  m /= n;
  for (int i = 0; i < n; i++)
    v += (x[i] - m) * (x[i] - m);
  return sqrt (v / n);
}

/* Columns whose response differs strongly from their neighbours (dead or hot pixels). */
static int
bad_columns (const double *hp, int n, int w, gboolean *bad)
{
  g_autofree double *col_std = g_new (double, w);
  g_autofree double *ref = g_new (double, w);
  g_autofree double *absdev = g_new (double, w);
  g_autofree double *nb = g_new0 (double, w);
  double mad, nb_med;
  int count = 0;

  for (int c = 0; c < w; c++)
    {
      g_autofree double *col = column (hp, n, w, c);
      col_std[c] = stddev (col, n);
    }
  median_filter (col_std, ref, w, 7);
  for (int c = 0; c < w; c++)
    absdev[c] = fabs (col_std[c] - ref[c]);
  mad = median (absdev, w) * 1.4826 + EPS;

  for (int c = 1; c < w - 1; c++)
    {
      double ma = 0, mb = 0, dot = 0, na = 0, nbn = 0;
      for (int r = 0; r < n; r++)
        {
          ma += hp[(gsize) r * w + c];
          mb += (hp[(gsize) r * w + c - 1] + hp[(gsize) r * w + c + 1]) / 2;
        }
      ma /= n;
      mb /= n;
      for (int r = 0; r < n; r++)
        {
          double a = hp[(gsize) r * w + c] - ma;
          double b = (hp[(gsize) r * w + c - 1] + hp[(gsize) r * w + c + 1]) / 2 - mb;
          dot += a * b;
          na += a * a;
          nbn += b * b;
        }
      nb[c] = dot / (sqrt (na) * sqrt (nbn) + EPS);
    }
  nb[0] = nb[1];
  nb[w - 1] = nb[w - 2];
  nb_med = median (nb, w);

  for (int c = 0; c < w; c++)
    {
      bad[c] = absdev[c] / mad > 6.0 || nb[c] < nb_med - 0.6;
      count += bad[c];
    }
  return count;
}

/* Replace bad columns by interpolating from the nearest good ones, row by row. */
static void
repair_columns (double *x, int n, int w, const gboolean *bad)
{
  g_autofree double *xp = g_new (double, w);
  g_autofree double *fp = g_new (double, w);
  int ngood = 0;

  for (int c = 0; c < w; c++)
    if (!bad[c])
      xp[ngood++] = c;
  if (ngood == w || ngood < 2)
    return;
  for (int r = 0; r < n; r++)
    {
      double *row = x + (gsize) r * w;
      for (int k = 0; k < ngood; k++)
        fp[k] = row[(int) xp[k]];
      for (int c = 0; c < w; c++)
        if (bad[c])
          row[c] = interp (c, xp, fp, ngood);
    }
}

/* Rows where the finger is on the sensor, from the high-passed ridge energy. */
static void
finger_region (const double *hp, int n, int w, int *lo, int *hi)
{
  g_autofree double *e = g_new (double, n);
  g_autofree double *energy = g_new (double, n);
  double base, peak, thr;

  for (int r = 0; r < n; r++)
    {
      double s = 0;
      for (int c = 0; c < w; c++)
        s += fabs (hp[(gsize) r * w + c]);
      e[r] = s / w;
    }
  gaussian_filter (e, energy, n, ENERGY_SIGMA);
  if (n > 400)
    {
      int q = (n + 3) / 4; /* Python: energy[-len(energy) // 4:], i.e. the last ceil(n / 4) */
      base = median (energy + n - q, q);
    }
  else
    {
      base = energy[0];
      for (int r = 1; r < n; r++)
        base = MIN (base, energy[r]);
    }
  peak = energy[0];
  for (int r = 1; r < n; r++)
    peak = MAX (peak, energy[r]);
  thr = base + 0.12 * (peak - base);

  *lo = -1;
  *hi = n;
  for (int r = 0; r < n; r++)
    if (energy[r] > thr)
      {
        if (*lo < 0)
          *lo = r;
        *hi = r + 1;
      }
  if (*lo < 0)
    {
      *lo = 0;
      *hi = n;
    }
}

/*
 * Per-line lag between aux and main lines, with a correlation confidence, for lines lo..hi-1.
 * Correlations are computed on [lo - WINDOW/2, hi + WINDOW/2) only, which is all the moving
 * average needs for those lines (reflected indices near 0 or n fall inside that span too).
 */
static void
estimate_lag (const double *lines, int n, int lo, int hi, int *lag, double *conf)
{
  const int half = WINDOW / 2;
  const int a = MAX (0, lo - half);
  const int b = MIN (n, hi + half);
  g_autofree double *main_part = g_new (double, (gsize) n * VFS495_MAIN_WIDTH);
  g_autofree double *aux_part = g_new (double, (gsize) n * AUX_WIDTH);
  g_autofree double *aux = g_new (double, (gsize) n * AUX_WIDTH);
  g_autofree double *m = g_new (double, (gsize) n * AUX_WIDTH);
  g_autofree double *p = g_new (double, n);
  g_autofree double *c = g_new (double, n);
  g_autofree double *hp = NULL;
  g_autofree double *aux_hp = NULL;

  for (int r = 0; r < n; r++)
    {
      memcpy (main_part + (gsize) r * VFS495_MAIN_WIDTH, lines + (gsize) r * VFS495_LINE_WIDTH,
              VFS495_MAIN_WIDTH * sizeof (double));
      for (int k = 0; k < AUX_WIDTH; k++)
        aux_part[(gsize) r * AUX_WIDTH + k] = -lines[(gsize) r * VFS495_LINE_WIDTH + AUX_START + k];
    }
  hp = highpass (main_part, n, VFS495_MAIN_WIDTH);
  aux_hp = highpass (aux_part, n, AUX_WIDTH);
  for (int r = 0; r < n; r++)
    unit_row (aux_hp + (gsize) r * AUX_WIDTH, aux + (gsize) r * AUX_WIDTH, AUX_WIDTH);

  for (int r = 0; r < n; r++)
    {
      conf[r] = -1.0;
      lag[r] = 0;
    }
  for (int c0 = C0_FIRST; c0 <= C0_LAST; c0++)
    {
      /* line t is compared with main row t + tau, so rows up to b - 1 + MAX_LAG are needed */
      for (int r = a; r < MIN (n, b + MAX_LAG); r++)
        unit_row (hp + (gsize) r * VFS495_MAIN_WIDTH + c0, m + (gsize) r * AUX_WIDTH, AUX_WIDTH);
      for (int tau = 1; tau <= MAX_LAG; tau++)
        {
          for (int t = a; t < b; t++)
            {
              if (t + tau >= n)
                {
                  p[t] = -1.0;
                  continue;
                }
              const double *x = aux + (gsize) t * AUX_WIDTH;
              const double *y = m + (gsize) (t + tau) * AUX_WIDTH;
              double s0 = 0, s1 = 0, s2 = 0, s3 = 0;
              for (int k = 0; k < AUX_WIDTH; k += 4)
                {
                  s0 += x[k] * y[k];
                  s1 += x[k + 1] * y[k + 1];
                  s2 += x[k + 2] * y[k + 2];
                  s3 += x[k + 3] * y[k + 3];
                }
              p[t] = (s0 + s1) + (s2 + s3);
            }
          box_filter_range (p, c, n, WINDOW, lo, hi);
          for (int t = lo; t < hi; t++)
            if (c[t] > conf[t])
              {
                conf[t] = c[t];
                lag[t] = tau;
              }
        }
    }
}

/* True where a line nearly repeats the line STILL_LAG earlier: the finger is not moving. */
static void
stationary (const double *hp, int n, int w, gboolean *still)
{
  g_autofree double *u = g_new (double, (gsize) n * w);
  g_autofree double *sim = g_new (double, n);
  g_autofree double *smooth = g_new (double, n);

  for (int r = 0; r < n; r++)
    unit_row (hp + (gsize) r * w, u + (gsize) r * w, w);
  for (int r = 0; r < n; r++)
    {
      if (r < STILL_LAG)
        {
          sim[r] = 1.0;
          continue;
        }
      double s = 0;
      for (int c = 0; c < w; c++)
        s += u[(gsize) r * w + c] * u[(gsize) (r - STILL_LAG) * w + c];
      sim[r] = s;
    }
  box_filter (sim, smooth, n, 15);
  for (int r = 0; r < n; r++)
    still[r] = smooth[r] > STILL_THRESHOLD;
}

/*
 * Positions of lines first..last-1 in output pixels. A lag is trusted when it is confident,
 * plausible, the finger is moving, and it points at a main line where the finger also moves.
 * The print is the longest run of trusted lags, extended by one lag at each end.
 */
static double *
positions (const int *lag, const double *conf, const gboolean *still, int n, int lo, int hi,
           int *first_out, int *last_out, GError **error)
{
  g_autofree int *ok = g_new (int, n);
  g_autofree double *okx = NULL;
  g_autofree double *lagv = NULL;
  g_autofree double *smooth = NULL;
  int nok = 0, best_start = 0, best_len = 0, run_start = 0;
  int first, last;
  double *y;

  for (int t = lo; t < hi; t++)
    {
      int target = CLAMP (t + lag[t], 0, n - 1);
      if (conf[t] >= CONF_MIN && !still[t] && !still[target] &&
          lag[t] >= MIN_TRUSTED_LAG && lag[t] <= MAX_TRUSTED_LAG)
        ok[nok++] = t;
    }
  if (nok < 10)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "no usable motion in this swipe");
      return NULL;
    }
  /* longest run allowing gaps up to RUN_GAP (ties: first run, like numpy.argmax) */
  for (int i = 1; i <= nok; i++)
    if (i == nok || ok[i] - ok[i - 1] > RUN_GAP)
      {
        if (i - run_start - 1 > best_len - 1)
          {
            best_start = run_start;
            best_len = i - run_start;
          }
        run_start = i;
      }

  okx = g_new (double, best_len);
  lagv = g_new (double, best_len);
  smooth = g_new (double, best_len);
  for (int i = 0; i < best_len; i++)
    {
      okx[i] = ok[best_start + i];
      lagv[i] = lag[ok[best_start + i]];
    }
  median_filter (lagv, smooth, best_len, 61);

  first = MAX (lo, (int) (okx[0] - smooth[0]));
  last = MIN (hi, (int) (okx[best_len - 1] + smooth[best_len - 1]) + 1);
  y = g_new (double, last - first);
  y[0] = 0;
  for (int t = first; t < last - 1; t++)
    {
      double speed = still[t] ? 0.0 : LINE_DISTANCE / interp (t, okx, smooth, best_len);
      y[t - first + 1] = y[t - first] + speed;
    }
  *first_out = first;
  *last_out = last;
  return y;
}

/* Evenly spaced rows: lines are averaged into their nearest row, empty rows interpolated. */
static double *
resample (const double *img, int n, int w, const double *y, int *rows_out)
{
  int rows = (int) floor (y[n - 1] + 0.5) + 1;
  double *out = g_new0 (double, (gsize) rows * w);
  g_autofree double *cnt = g_new0 (double, rows);
  g_autofree double *xp = g_new (double, rows);
  g_autofree double *fp = g_new (double, rows);
  int nfilled = 0;

  for (int t = 0; t < n; t++)
    {
      int b = CLAMP ((int) floor (y[t] + 0.5), 0, rows - 1);
      for (int c = 0; c < w; c++)
        out[(gsize) b * w + c] += img[(gsize) t * w + c];
      cnt[b] += 1;
    }
  for (int r = 0; r < rows; r++)
    if (cnt[r] > 0)
      {
        for (int c = 0; c < w; c++)
          out[(gsize) r * w + c] /= cnt[r];
        xp[nfilled++] = r;
      }
  for (int c = 0; c < w; c++)
    {
      for (int k = 0; k < nfilled; k++)
        fp[k] = out[(gsize) xp[k] * w + c];
      for (int r = 0; r < rows; r++)
        if (cnt[r] == 0)
          out[(gsize) r * w + c] = interp (r, xp, fp, nfilled);
    }
  *rows_out = rows;
  return out;
}

/*
 * Region measurements for diagnosing rejected swipes. gain holds each column's ridge contrast
 * inside the region, before equalisation.
 */
static void
measure_region (const int *lag, const double *conf, const gboolean *still, const double *gain, int n, int w,
                int lo, int hi, Vfs495AssembleInfo *info)
{
  g_autofree double *lags = g_new (double, MAX (1, hi - lo));
  g_autofree double *sorted = g_memdup2 (gain, w * sizeof (double));
  int nconf = 0, nfast = 0, nlags = 0, nstill = 0, ncov = 0;
  double p90;

  for (int t = lo; t < hi; t++)
    {
      int target = CLAMP (t + lag[t], 0, n - 1);

      nstill += still[t];
      if (conf[t] < CONF_MIN)
        continue;
      nconf++;
      if (lag[t] < MIN_TRUSTED_LAG)
        nfast++;
      if (!still[t] && !still[target] && lag[t] >= MIN_TRUSTED_LAG && lag[t] <= MAX_TRUSTED_LAG)
        lags[nlags++] = lag[t];
    }
  qsort (sorted, w, sizeof (double), cmp_double);
  p90 = sorted[(int) (0.9 * (w - 1))];
  for (int c = 0; c < w; c++)
    ncov += gain[c] > 0.35 * p90;

  info->region_lines = hi - lo;
  info->trusted = nlags;
  info->still_fraction = (double) nstill / MAX (1, hi - lo);
  info->confident = (double) nconf / MAX (1, hi - lo);
  info->fast = (double) nfast / MAX (1, nconf);
  info->median_lag = nlags ? median (lags, nlags) : 0;
  info->coverage = (double) ncov / w;
}

guint8 *
vfs495_assemble (const guint8 *lines8, int n, Vfs495AssembleInfo *info, GError **error)
{
  const int w = VFS495_MAIN_WIDTH;
  g_autofree double *lines = g_new (double, (gsize) n * VFS495_LINE_WIDTH);
  g_autofree double *main_raw = g_new (double, (gsize) n * w);
  g_autofree double *hp0 = NULL;
  g_autofree double *hp = NULL;
  g_autofree gboolean *bad = g_new0 (gboolean, w);
  g_autofree int *lag = g_new (int, n);
  g_autofree double *conf = g_new (double, n);
  g_autofree gboolean *still = g_new (gboolean, n);
  g_autofree double *y = NULL;
  g_autofree double *img = NULL;
  g_autofree double *gain = g_new (double, w);
  g_autofree double *absdev = NULL;
  g_autofree double *out = NULL;
  int lo, hi, first, last, rows, nbad, nseg;
  double gain_med, lo_p, hi_p;
  guint8 *u8;

  memset (info, 0, sizeof *info);
  if (n < 100)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "swipe too short");
      return NULL;
    }
  for (gsize i = 0; i < (gsize) n * VFS495_LINE_WIDTH; i++)
    lines[i] = lines8[i];
  for (int r = 0; r < n; r++)
    memcpy (main_raw + (gsize) r * w, lines + (gsize) r * VFS495_LINE_WIDTH, w * sizeof (double));

  /* column defects, then the filtered main lines used for region and stillness */
  hp0 = highpass (main_raw, n, w);
  nbad = bad_columns (hp0, n, w, bad);
  repair_columns (main_raw, n, w, bad);
  hp = highpass (main_raw, n, w);
  finger_region (hp, n, w, &lo, &hi);
  nseg = hi - lo;
  for (int c = 0; c < w; c++)
    {
      g_autofree double *col = g_new (double, nseg);
      for (int r = 0; r < nseg; r++)
        col[r] = hp[(gsize) (lo + r) * w + c];
      gain[c] = stddev (col, nseg);
    }
  gain_med = median (gain, w);
  for (int r = 0; r < n; r++)
    for (int c = 0; c < w; c++)
      hp[(gsize) r * w + c] /= gain[c] / gain_med + 1e-3;

  estimate_lag (lines, n, lo, hi, lag, conf);
  stationary (hp, n, w, still);
  measure_region (lag, conf, still, gain, n, w, lo, hi, info);
  y = positions (lag, conf, still, n, lo, hi, &first, &last, error);
  if (!y)
    return NULL;

  /* output from near-raw pixels: per-column offset and spread from the print area only */
  nseg = last - first;
  img = g_new (double, (gsize) nseg * w);
  absdev = g_new (double, nseg);
  {
    g_autofree double *spread = g_new (double, w);
    double spread_med;

    for (int c = 0; c < w; c++)
      {
        g_autofree double *col = g_new (double, nseg);
        for (int r = 0; r < nseg; r++)
          col[r] = main_raw[(gsize) (first + r) * w + c];
        double med = median (col, nseg);
        for (int r = 0; r < nseg; r++)
          {
            img[(gsize) r * w + c] = col[r] - med;
            absdev[r] = fabs (col[r] - med);
          }
        spread[c] = median (absdev, nseg) + 1e-3;
      }
    spread_med = median (spread, w);
    for (int r = 0; r < nseg; r++)
      for (int c = 0; c < w; c++)
        img[(gsize) r * w + c] /= spread[c] / spread_med;
  }
  out = resample (img, nseg, w, y, &rows);

  lo_p = percentile (out, rows * w, 1);
  hi_p = percentile (out, rows * w, 99);
  u8 = g_new (guint8, (gsize) rows * w);
  for (gsize i = 0; i < (gsize) rows * w; i++)
    u8[i] = (guint8) CLAMP ((out[i] - lo_p) / (hi_p - lo_p) * 255.0, 0, 255);

  info->first_line = first;
  info->last_line = last;
  info->rows = rows;
  info->bad_columns = nbad;
  return u8;
}

#define MIN_ROWS           80     /* a usable swipe stitches to ~150-400 rows */
#define RESTING_STILL      0.9
#define RESTING_TRUSTED    10
#define MIN_COVERAGE       0.6
#define MAX_FAST           0.25

Vfs495SwipeVerdict
vfs495_swipe_verdict (const guint8 *image, const Vfs495AssembleInfo *info)
{
  if (info->region_lines == 0)
    return VFS495_SWIPE_TOO_SHORT;
  if (info->still_fraction >= RESTING_STILL && info->trusted < RESTING_TRUSTED)
    return VFS495_SWIPE_RESTING;
  if (info->coverage < MIN_COVERAGE)
    return VFS495_SWIPE_OFF_CENTRE;
  if (info->fast >= MAX_FAST)
    return VFS495_SWIPE_TOO_FAST;
  if (!image || info->rows < MIN_ROWS)
    return VFS495_SWIPE_TOO_SHORT;
  return VFS495_SWIPE_OK;
}

const char *
vfs495_swipe_verdict_name (Vfs495SwipeVerdict verdict)
{
  switch (verdict)
    {
    case VFS495_SWIPE_OK:
      return "ok";
    case VFS495_SWIPE_TOO_SHORT:
      return "too short";
    case VFS495_SWIPE_RESTING:
      return "finger resting";
    case VFS495_SWIPE_OFF_CENTRE:
      return "off centre";
    case VFS495_SWIPE_TOO_FAST:
      return "too fast";
    }
  return "?";
}
