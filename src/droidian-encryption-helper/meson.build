droidian_encryption_helper_sources = [
  'droidian-encryption-helper.c',
]

droidian_encryption_helper_deps = [
  dependency('glib-2.0'),
  dependency('gobject-2.0'),
  dependency('gio-2.0'),
  dependency('gio-unix-2.0'),
  dependency('libcryptsetup'),
]

executable('droidian-encryption-helper', droidian_encryption_helper_sources,
  dependencies: droidian_encryption_helper_deps,
  install: true,
  install_dir: get_option('sbindir')
)

install_data('droidian-encryption-helper-shutdown.sh',
  rename: 'droidian-encryption-helper-shutdown',
  install_dir: get_option('sbindir')
)
