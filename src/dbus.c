/* dbus.c
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

#define G_LOG_DOMAIN "droidian-encryption-service-dbus"

#include "dbus.h"

struct _DroidianEncryptionServiceDbus
{
  GObject parent_instance;

  uint owned_id;
  uint devicestate_id;

  gint64 last_call_timestamp;

  GDBusConnection *connection;
};

enum {
  SIGNAL_BUS_ACQUIRED,
  SIGNAL_TIMEOUT_REACHED,
  N_SIGNALS
};
static uint signals[N_SIGNALS] = { 0 };

G_DEFINE_TYPE (DroidianEncryptionServiceDbus, droidian_encryption_service_dbus, G_TYPE_OBJECT)

static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 DroidianEncryptionServiceDbus      *self)
{
  g_return_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_DBUS (self));

  g_debug ("Bus acquired: %s!", name);

  self->connection = connection;

  g_signal_emit (self, signals[SIGNAL_BUS_ACQUIRED], 0, connection);

}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  DroidianEncryptionServiceDbus      *self)
{
  g_return_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_DBUS (self));

  g_debug ("Name acquired: %s!", name);
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              DroidianEncryptionServiceDbus      *self)
{
  g_return_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_DBUS (self));

  g_debug ("Name lost: %s!", name);
}

static gboolean
on_idle_timeout_elapsed (DroidianEncryptionServiceDbus *self)
{
  g_return_val_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_DBUS (self), G_SOURCE_REMOVE);

  g_warning ("Timeout callback");

  if ((g_get_monotonic_time () - self->last_call_timestamp) > 300 * 1000000)
    {
      /* More than five minutes since the last call, tell listeners we can exit */
      g_signal_emit (self, signals[SIGNAL_TIMEOUT_REACHED], 0, self);
      return G_SOURCE_REMOVE;
    }

  return G_SOURCE_CONTINUE;
}

void
droidian_encryption_service_dbus_register_timestamp (DroidianEncryptionServiceDbus *self)
{
  g_return_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_DBUS (self));

  self->last_call_timestamp = g_get_monotonic_time ();
}

GDBusConnection*
droidian_encryption_service_dbus_get_connection (DroidianEncryptionServiceDbus *self)
{
  g_return_val_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_DBUS (self), NULL);

  return self->connection;
}

static void
droidian_encryption_service_dbus_constructed (GObject *obj)
{
  DroidianEncryptionServiceDbus *self = DROIDIAN_ENCRYPTION_SERVICE_DBUS (obj);

  G_OBJECT_CLASS (droidian_encryption_service_dbus_parent_class)->constructed (obj);

  self->devicestate_id = 0;
  self->owned_id = 0;
  self->connection = NULL;

  /* Start idle timeout */
  droidian_encryption_service_dbus_register_timestamp (self);
  g_timeout_add_seconds (60, G_SOURCE_FUNC (on_idle_timeout_elapsed), self);
}

void
droidian_encryption_service_dbus_own_name (DroidianEncryptionServiceDbus *self)
{
  g_return_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_DBUS (self));

  if (!self->owned_id)
      self->owned_id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
                                       "org.droidian.EncryptionService",
                                       G_BUS_NAME_OWNER_FLAGS_NONE,
                                       (GBusAcquiredCallback) on_bus_acquired,
                                       (GBusNameAcquiredCallback) on_name_acquired,
                                       (GBusNameLostCallback) on_name_lost,
                                       self,
                                       NULL);

}

static void
droidian_encryption_service_dbus_dispose (GObject *obj)
{
  DroidianEncryptionServiceDbus *self = DROIDIAN_ENCRYPTION_SERVICE_DBUS (obj);

  g_debug ("Dbus dispose");

  G_OBJECT_CLASS (droidian_encryption_service_dbus_parent_class)->dispose (obj);

  g_bus_unown_name (self->owned_id);
}

static void
droidian_encryption_service_dbus_class_init (DroidianEncryptionServiceDbusClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->constructed  = droidian_encryption_service_dbus_constructed;
  object_class->dispose      = droidian_encryption_service_dbus_dispose;

  signals[SIGNAL_BUS_ACQUIRED] =
  g_signal_new ("bus-acquired",
                G_TYPE_FROM_CLASS (klass),
                G_SIGNAL_RUN_LAST,
                0,
                NULL,
                NULL,
                NULL,
                G_TYPE_NONE,
                1,
                G_TYPE_OBJECT);

  signals[SIGNAL_TIMEOUT_REACHED] =
  g_signal_new ("timeout-reached",
                G_TYPE_FROM_CLASS (klass),
                G_SIGNAL_RUN_LAST,
                0,
                NULL,
                NULL,
                NULL,
                G_TYPE_NONE,
                1,
                G_TYPE_OBJECT);
}

static void
droidian_encryption_service_dbus_init (DroidianEncryptionServiceDbus *self)
{
}

DroidianEncryptionServiceDbus *
droidian_encryption_service_dbus_get_default (void)
{
  static DroidianEncryptionServiceDbus *instance = NULL;
  static GMutex mutex;

  g_mutex_lock (&mutex);

  if (instance == NULL)
    {
      instance = g_object_new (DROIDIAN_ENCRYPTION_SERVICE_TYPE_DBUS, NULL);
      g_object_add_weak_pointer (G_OBJECT (instance), (gpointer) &instance);
    }
  else
    {
      g_object_ref (instance);
    }

  g_mutex_unlock (&mutex);

  return instance;
}

