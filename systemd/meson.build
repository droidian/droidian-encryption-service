# TODO: make systemd dependency optional
systemd_dep = dependency('systemd')

install_data(
  ['droidian-encryption-service.service', 'droidian-encryption-helper-shutdown.service'],
  install_dir: systemd_dep.get_pkgconfig_variable('systemdsystemunitdir')
)
