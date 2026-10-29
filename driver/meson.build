project('vfs495-driver', 'c',
  version: '0.6.0',
  default_options: ['c_std=gnu11', 'warning_level=2', 'buildtype=release'])

cc = meson.get_compiler('c')
add_project_arguments('-DVFS495_VERSION="@0@"'.format(meson.project_version()), language: 'c')
glib = dependency('glib-2.0')
gio = dependency('gio-2.0')
gmodule = dependency('gmodule-2.0')
m = cc.find_library('m')
gusb = dependency('gusb')
libcrypto = dependency('libcrypto')
libfprint_tod = dependency('libfprint-2-tod-1')
libfprint = dependency('libfprint-2')

# -Dfuzz=true builds libFuzzer fuzzers instead of corpus replayers (clang only): the code
# under test is instrumented for coverage.
if get_option('fuzz')
  if cc.get_id() != 'clang'
    error('-Dfuzz=true needs clang: CC=clang meson setup ...')
  endif
  add_project_arguments('-fsanitize=fuzzer-no-link', language: 'c')
endif

# -Dnative=true tunes for the build machine; packages are built for generic x86-64.
if get_option('native')
  add_project_arguments('-march=native', language: 'c')
endif

assemble = static_library('vfs495-assemble', 'src/vfs495-assemble.c',
  dependencies: [glib, gio, m],
  gnu_symbol_visibility: 'hidden',
  pic: true)

protocol = static_library('vfs495-protocol',
  'src/vfs495-commands.c', 'src/vfs495-protocol.c', 'src/vfs495-image.c',
  dependencies: [glib, gio, libcrypto],
  gnu_symbol_visibility: 'hidden',
  pic: true)

executable('vfs495-tool', 'src/vfs495-tool.c', 'src/vfs495-proto.c',
  link_with: [assemble, protocol],
  dependencies: [glib, gio, gusb, libcrypto, m])

# The libfprint driver, loaded by libfprint's TOD loader from
# libfprint_tod.get_variable('tod_driversdir') (or $FP_TOD_DRIVERS_DIR).
# Linked against libfprint-2 too (fp_image_new and the image device type are public API), so
# the module resolves every symbol through its own dependencies, whatever the host process;
# -z defs turns a symbol the libraries do not export into a build error (not in sanitizer
# builds, whose runtime symbols are resolved at load time).
module = shared_module('fprint-tod-vfs495', 'src/vfs495.c', 'src/vfs495-diag.c',
  link_with: [assemble, protocol],
  dependencies: [libfprint_tod, libfprint, glib, gio, gmodule, gusb, libcrypto, m],
  c_args: ['-Wno-unused-parameter'],
  link_args: get_option('b_sanitize') == 'none' ? ['-Wl,-z,defs'] : [],
  gnu_symbol_visibility: 'hidden',
  install: true,
  install_dir: libfprint_tod.get_variable(pkgconfig: 'tod_driversdir'))

# Tests without recorded data: the stitcher on simulated swipes, the stream decoder, the
# command parser, the session crypto, signed patches and the beta diagnostics. Run anywhere,
# including CI.
unit = executable('vfs495-unit', 'tests/vfs495-unit.c', 'tests/vfs495-sim.c', 'src/vfs495-diag.c',
  include_directories: 'src',
  link_with: [assemble, protocol],
  dependencies: [glib, gio, libcrypto, m])
test('unit', unit, protocol: 'tap', args: ['--tap'], timeout: 300)

# Regression tests. Their data (recordings, scans) is private and lives in the git-ignored
# captures/ folder; tests without data are skipped. Update expectations after an intended
# change with: build/driver/vfs495-test --update driver/tests/golden.txt captures
tests = executable('vfs495-test', 'tests/vfs495-test.c',
  include_directories: 'src',
  link_with: [assemble, protocol],
  dependencies: [glib, gio, libcrypto, m])
test('regression', tests,
  args: [meson.project_source_root() / 'tests' / 'golden.txt',
         meson.project_source_root() / '..' / 'captures'],
  timeout: 600)

# The whole driver inside libfprint, replayed from USB recordings made with
# tests/umockdev/record.sh (private: they hold a fingerprint scan); skipped without them. Not in
# sanitizer builds, whose module cannot load into an uninstrumented Python.
if get_option('b_sanitize') == 'none'
  test('umockdev', find_program('tests/umockdev/replay.sh'),
    args: [meson.current_build_dir(), meson.project_source_root() / '..' / 'captures' / 'umockdev'],
    depends: module,
    timeout: 120)
endif

# Fuzz targets for the code that parses untrusted bytes (fuzz/README). Normally each is a
# replayer of saved inputs, run by meson test against the private corpus in
# captures/fuzz/TARGET (skipped without it); with -Dfuzz=true each is a libFuzzer fuzzer.
fuzz_corpus = meson.project_source_root() / '..' / 'captures' / 'fuzz'
foreach t : ['commands', 'records', 'frames', 'assemble']
  if get_option('fuzz')
    executable('fuzz-' + t, 'fuzz/fuzz-' + t + '.c',
      include_directories: 'src',
      link_with: [assemble, protocol],
      dependencies: [glib, gio, libcrypto, m],
      link_args: ['-fsanitize=fuzzer'])
  else
    replay = executable('fuzz-' + t + '-replay', 'fuzz/fuzz-' + t + '.c', 'fuzz/run-corpus.c',
      include_directories: 'src',
      link_with: [assemble, protocol],
      dependencies: [glib, gio, libcrypto, m])
    test('fuzz-corpus-' + t, replay, args: [fuzz_corpus / t], timeout: 600)
  endif
endforeach

