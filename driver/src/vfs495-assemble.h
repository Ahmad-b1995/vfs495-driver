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
} Vfs495AssembleInfo;

/*
 * lines: n_lines x VFS495_LINE_WIDTH descrambled 8-bit pixels.
 * Returns a newly allocated VFS495_MAIN_WIDTH x info->rows 8-bit image (ridges dark), or NULL
 * with error set when the swipe has no usable motion (too short, finger never moved).
 */
guint8 *vfs495_assemble (const guint8       *lines,
                         int                 n_lines,
                         Vfs495AssembleInfo *info,
                         GError            **error);
