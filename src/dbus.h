/* dbus.h
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

#ifndef DROIDIANENCRYPTIONSERVICEDBUS_H
#define DROIDIANENCRYPTIONSERVICEDBUS_H

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define DROIDIAN_ENCRYPTION_SERVICE_TYPE_DBUS droidian_encryption_service_dbus_get_type ()
G_DECLARE_FINAL_TYPE (DroidianEncryptionServiceDbus, droidian_encryption_service_dbus,
                      DROIDIAN_ENCRYPTION_SERVICE, DBUS, GObject)

DroidianEncryptionServiceDbus *droidian_encryption_service_dbus_get_default (void);
void droidian_encryption_service_dbus_own_name (DroidianEncryptionServiceDbus *self);
void droidian_encryption_service_dbus_register_timestamp (DroidianEncryptionServiceDbus *self);
GDBusConnection *droidian_encryption_service_dbus_get_connection (DroidianEncryptionServiceDbus *self);

G_END_DECLS

#endif /* DROIDIANENCRYPTIONSERVICEDBUS_H */

