/* config.h
 *
 * Copyright 2022 Eugenio Paolantonio (g7)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DROIDIANENCRYPTIONSERVICECONFIG_H
#define DROIDIANENCRYPTIONSERVICECONFIG_H

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define DROIDIAN_ENCRYPTION_SERVICE_TYPE_CONFIG droidian_encryption_service_config_get_type ()
G_DECLARE_FINAL_TYPE (DroidianEncryptionServiceConfig, droidian_encryption_service_config,
                      DROIDIAN_ENCRYPTION_SERVICE, CONFIG, GObject)

DroidianEncryptionServiceConfig *droidian_encryption_service_config_get_default (void);
char *droidian_encryption_service_config_get_header_device (DroidianEncryptionServiceConfig *self);
char *droidian_encryption_service_config_get_data_device (DroidianEncryptionServiceConfig *self);
char *droidian_encryption_service_config_get_mapped_name (DroidianEncryptionServiceConfig *self);
char *droidian_encryption_service_config_get_cipher (DroidianEncryptionServiceConfig *self);
char *droidian_encryption_service_config_get_cipher_mode (DroidianEncryptionServiceConfig *self);

G_END_DECLS

#endif /* DROIDIANENCRYPTIONSERVICEDBUS_H */

