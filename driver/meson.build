project('vfs495-driver', 'c',
  version: '0.1.0',
  default_options: ['c_std=gnu11', 'warning_level=2', 'buildtype=release'])

cc = meson.get_compiler('c')
glib = dependency('glib-2.0')
gio = dependency('gio-2.0')
m = cc.find_library('m')
gusb = dependency('gusb')
libcrypto = dependency('libcrypto')

# Built for this machine only.
add_project_arguments('-march=native', language: 'c')

assemble = static_library('vfs495-assemble', 'src/vfs495-assemble.c',
  dependencies: [glib, gio, m],
  pic: true)

sensor = static_library('vfs495-sensor', 'src/vfs495-proto.c', 'src/vfs495-image.c',
  dependencies: [glib, gio, gusb, libcrypto],
  pic: true)

executable('vfs495-tool', 'src/vfs495-tool.c',
  link_with: [assemble, sensor],
  dependencies: [glib, gio, gusb, libcrypto, m])
