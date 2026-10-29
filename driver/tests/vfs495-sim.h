/*
 * A simulated VFS495: synthetic fingers swiped over the sensor's two sensing lines, as scan
 * lines and as the encrypted frame stream the sensor sends. No recorded data, so the tests
 * built on it can be published and run anywhere.
 *
 * The model follows the README: 264-pixel lines, the main line in columns 0-199 (ridges dark),
 * an auxiliary line in columns 200-263 with inverted polarity over main columns 68-131 that
 * sits LINE_DISTANCE (8) pixels ahead in the swipe direction, so a ridge reaches the main line
 * 8 / speed lines after the aux line. Pixel levels and noise are those of recorded scans: about
 * 122 without a finger, ridges and valleys about 70 either side of 127 under one.
 */
#pragma once

#include <glib.h>

#include "vfs495-image.h"

#define SIM_FINGER_WIDTH   VFS495_MAIN_WIDTH
#define SIM_AUX_OVER       68      /* main column under aux pixel 0 */
#define SIM_LINE_DISTANCE  8.0

/* a fingertip print, SIM_FINGER_WIDTH x height, 0 = ridge .. 255 = valley; contact[] says
 * how firmly each pixel touches (0 = outside the finger) */
typedef struct
{
  int     height;
  guint8 *ridges;
  float  *contact;
} SimFinger;

SimFinger *sim_finger_new  (guint32 seed,
                            int     height);
void       sim_finger_free (SimFinger *f);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (SimFinger, sim_finger_free)

typedef struct
{
  guint32 seed;          /* noise */
  double  speed_start;   /* finger travel in pixels per line, at the start and at the end */
  double  speed_end;
  double  start_row;     /* finger row under the main line at the start */
  double  travel;        /* pixels of finger that pass the main line */
  int     rest_lines;    /* lines the finger rests before it moves */
  int     tail_lines;    /* lines after the finger has left */
  int     left, right;   /* sensor columns the finger covers, [left, right) */
  int     dead_column;   /* a column stuck at 0, or -1 */
  double  noise;         /* standard deviation of pixel noise */
} SimSwipe;

/* a normal swipe of a 600-row finger: 0.3 px per line over 560 pixels, centred, mild noise,
 * and 1200 lines after the finger has left (the sensor streams on for about that long) */
SimSwipe sim_swipe_default (void);

/*
 * The scan lines of a swipe: *n_lines x VFS495_LINE_WIDTH pixels in image column order.
 */
guint8 *sim_swipe_lines (const SimFinger *finger,
                         const SimSwipe  *swipe,
                         int             *n_lines);

/* a column table like the sensor's (README finding 25): sensor column i -> image column */
void sim_descramble_table (guint16 table[VFS495_LINE_WIDTH]);

/*
 * The decrypted stream the sensor would send for these lines: 272-byte frames (01 fe, u16
 * sequence number, 4 bytes, 264 pixels in sensor column order) and a final status frame.
 * Frames listed in drop[] (n_drop of them, by line index) are left out.
 */
GByteArray *sim_frames (const guint8  *lines,
                        int            n_lines,
                        const guint16 *descramble,
                        const int     *drop,
                        int            n_drop);

/* AES-256-CBC, as the sensor encrypts the stream with the key the host chose when arming */
GByteArray *sim_encrypt (const GByteArray *plain,
                         const guint8      key[32],
                         const guint8      iv[16]);

/*
 * How well a stitched image (VFS495_MAIN_WIDTH x rows) reproduces the finger: blocks of rows
 * are each placed where they correlate best with the finger's ridges. correlation is their
 * mean normalised cross-correlation, scale the finger rows per image row from a line through
 * the placements (1 when the stitcher measured the speed right).
 */
typedef struct
{
  double correlation;
  double scale;
} SimMatch;

SimMatch sim_match (const SimFinger *finger,
                    const guint8    *image,
                    int              rows);
