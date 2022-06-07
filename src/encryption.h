/* encryption.h
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

#ifndef DROIDIANENCRYPTIONSERVICEENCRYPTION_H
#define DROIDIANENCRYPTIONSERVICEENCRYPTION_H

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>
#include <polkit/polkittypes.h>

#include "dbus-encryption.h"

G_BEGIN_DECLS

typedef enum {
  DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_UNKNOWN = 0,
  DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_UNSUPPORTED,
  DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_UNCONFIGURED,
  DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_CONFIGURING,
  DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_CONFIGURED,
  DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_ENCRYPTING,
  DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_ENCRYPTED,
  DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_FAILED,
} DroidianEncryptionServiceEncryptionStatus;

#define DROIDIAN_ENCRYPTION_SERVICE_TYPE_ENCRYPTION droidian_encryption_service_encryption_get_type ()
G_DECLARE_FINAL_TYPE (DroidianEncryptionServiceEncryption, droidian_encryption_service_encryption,
                      DROIDIAN_ENCRYPTION_SERVICE, ENCRYPTION, DroidianEncryptionServiceDbusEncryptionSkeleton)

DroidianEncryptionServiceEncryption *droidian_encryption_service_encryption_get_default (void);
DroidianEncryptionServiceEncryptionStatus droidian_encryption_service_encryption_get_last_status (DroidianEncryptionServiceEncryption *self);

G_END_DECLS

#endif /* DROIDIANENCRYPTIONSERVICEENCRYPTION_H */
