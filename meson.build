project('droidian-encryption-service', 'c',
          version: '0.1.3',
    meson_version: '>= 0.50.0',
  default_options: [ 'warning_level=2',
                     'c_std=gnu11',
                   ],
)

add_project_arguments([
  '-DPACKAGE_VERSION="@0@"'.format(meson.project_version())
], language: 'c')


subdir('src')
subdir('data')
subdir('systemd')
