/*
 * VFS495 swipe assembly: turn descrambled scan lines into a fingerprint image.
 *
 * Each 264-pixel line holds the main sensing line (columns 0-199) and a shorter auxiliary line
 * (columns 200-263, inverted polarity) that sits ahead of the main line in the swipe direction
 * over main columns ~68..131. A ridge reaches the main line `lag` lines after the aux line, so
 * the finger moves D / lag pixels per line. See research/quality/assemble.py for the reference
 * implementation this ports.
 */
#pragma once

#include <gio/gio.h>

#define VFS495_LINE_WIDTH  264
#define VFS495_MAIN_WIDTH  200

typedef struct
{
  int    first_line;     /* span of input lines that form the print */
  int    last_line;
  int    rows;           /* output height */
  int    bad_columns;    /* repaired dead or hot columns */
  double still_fraction; /* share of finger lines where the finger rested */

  /* measurements of the finger region, filled also when assembly fails */
  int    region_lines;   /* lines where the finger is on the sensor */
  int    trusted;        /* lines with a trusted speed estimate */
  double confident;      /* share of region lines with a confident lag */
  double fast;           /* share of confident lags below the trusted minimum (too fast) */
  double median_lag;     /* median trusted lag in lines (small: fast swipe) */
  double coverage;       /* share of columns carrying ridges (low: finger off to a side) */
} Vfs495AssembleInfo;

/*
 * lines: n_lines x VFS495_LINE_WIDTH descrambled 8-bit pixels.
 * Returns a newly allocated VFS495_MAIN_WIDTH x info->rows 8-bit image (ridges dark), or NULL
 * with error set when the swipe has no usable motion (too short, finger never moved). The
 * region measurements in info are filled whenever the swipe had at least 100 lines.
 */
guint8 *vfs495_assemble (const guint8       *lines,
                         int                 n_lines,
                         Vfs495AssembleInfo *info,
                         GError            **error);

typedef enum {
  VFS495_SWIPE_OK,
  VFS495_SWIPE_TOO_SHORT,   /* too few lines, or too short a print */
  VFS495_SWIPE_RESTING,     /* the finger rested on the sensor instead of moving */
  VFS495_SWIPE_OFF_CENTRE,  /* ridges on only part of the sensor's width */
  VFS495_SWIPE_TOO_FAST,    /* the finger outran the two sensing lines */
} Vfs495SwipeVerdict;

/*
 * Judge a swipe from vfs495_assemble's result (image may be NULL) and measurements. The limits
 * come from 44 normal swipes of three fingers over six sessions and 11 deliberately bad ones:
 * normal swipes were at most 15% too fast, at least 88% covered and at most 36% resting;
 * fast swipes were at least 30% too fast, off-centre ones at most 40% covered, and a resting
 * finger 100% still with no motion. See README, "Swipe feedback".
 */
Vfs495SwipeVerdict vfs495_swipe_verdict (const guint8             *image,
                                         const Vfs495AssembleInfo *info);

const char        *vfs495_swipe_verdict_name (Vfs495SwipeVerdict verdict);

