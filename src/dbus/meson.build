gnome = import('gnome')

gdbus_encryption = gnome.gdbus_codegen(
  'dbus-encryption',
  'org.droidian.EncryptionService.Encryption.xml',
  interface_prefix: 'org.droidian.EncryptionService',
  namespace: 'DroidianEncryptionServiceDbus'
)

install_data(
  'org.droidian.EncryptionService.conf',
  install_dir: get_option('datadir') / 'dbus-1/system.d/'
)

install_data(
  'org.droidian.EncryptionService.service',
  install_dir: get_option('datadir') / 'dbus-1/system-services/'
)

