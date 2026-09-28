project('vfs495-driver', 'c',
  version: '0.2.0',
  default_options: ['c_std=gnu11', 'warning_level=2', 'buildtype=release'])

cc = meson.get_compiler('c')
glib = dependency('glib-2.0')
gio = dependency('gio-2.0')
gmodule = dependency('gmodule-2.0')
m = cc.find_library('m')
gusb = dependency('gusb')
libcrypto = dependency('libcrypto')
libfprint_tod = dependency('libfprint-2-tod-1')

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
shared_module('fprint-tod-vfs495', 'src/vfs495.c',
  link_with: [assemble, protocol],
  dependencies: [libfprint_tod, glib, gio, gmodule, gusb, libcrypto, m],
  c_args: ['-Wno-unused-parameter'],
  gnu_symbol_visibility: 'hidden',
  install: true,
  install_dir: libfprint_tod.get_variable(pkgconfig: 'tod_driversdir'))
