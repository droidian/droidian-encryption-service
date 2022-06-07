subdir('dbus')
subdir('droidian-encryption-helper')

droidian_encryption_service_sources = [
  gdbus_encryption,
  'dbus.c',
  'config.c',
  'encryption.c',
  'droidian-encryption-service.c',
]

droidian_encryption_service_deps = [
  dependency('glib-2.0'),
  dependency('gobject-2.0'),
  dependency('gio-2.0'),
  dependency('gio-unix-2.0'),
  dependency('libcryptsetup'),
  dependency('polkit-gobject-1'),
  dependency('devmapper'),
]

executable('droidian-encryption-service', droidian_encryption_service_sources,
  dependencies: droidian_encryption_service_deps,
  install: true,
  install_dir: get_option('sbindir')
)
