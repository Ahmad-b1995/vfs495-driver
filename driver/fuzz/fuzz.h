/*
 * Fuzz targets for the code that parses untrusted bytes: data the sensor (or something
 * pretending to be it) sends, and the command file. Each target defines
 * LLVMFuzzerTestOneInput; built with clang -fsanitize=fuzzer it is a libFuzzer fuzzer, built
 * with run-corpus.c it replays saved inputs (meson test). See driver/fuzz/README.
 */
#pragma once

#include <glib.h>
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);
