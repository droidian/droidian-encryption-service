/* encryption.c
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

#define G_LOG_DOMAIN "droidian-encryption-service-encryption"

#include <libcryptsetup.h>
#include <libdevmapper.h>
#include <polkit/polkit.h>

#include "encryption.h"
#include "config.h"
#include "dbus.h"

#define DROIDIAN_ENCRYPTION_HELPER_PIDFILE "/run/droidian-encryption-helper.pid"
#define DROIDIAN_ENCRYPTION_HELPER_FAILURE "/run/droidian-encryption-helper-failed"

/* Workaround for the ancient polkit build in Debian */
#ifndef PolkitAuthorizationResult_autoptr
G_DEFINE_AUTOPTR_CLEANUP_FUNC (PolkitAuthorizationResult, g_object_unref)
#endif /* PolkitAuthorizationResult_autoptr */
#ifndef PolkitSubject_autoptr
G_DEFINE_AUTOPTR_CLEANUP_FUNC (PolkitSubject, g_object_unref)
#endif /* PolkitSubject_autoptr */

enum {
  DM_CRYPT_SECTOR_SIZE = 1 << 0,
};

struct _DroidianEncryptionServiceEncryption
{
  DroidianEncryptionServiceDbusEncryptionSkeleton parent_instance;

  /* instance members */
  DroidianEncryptionServiceDbus *dbus;
  DroidianEncryptionServiceConfig *config;
  gboolean interface_exported;
  PolkitAuthority *authority;
  GMutex encryption_process_mutex;
  GThread *encryption_process_thread;
  struct crypt_device *crypt_device;
  char *passphrase;
};

static void droidian_encryption_service_dbus_encryption_interface_init (DroidianEncryptionServiceDbusEncryptionIface *iface);

G_DEFINE_TYPE_WITH_CODE (DroidianEncryptionServiceEncryption, droidian_encryption_service_encryption,
                         DROIDIAN_ENCRYPTION_SERVICE_DBUS_TYPE_ENCRYPTION_SKELETON,
                         G_IMPLEMENT_INTERFACE (
                          DROIDIAN_ENCRYPTION_SERVICE_DBUS_TYPE_ENCRYPTION,
                          droidian_encryption_service_dbus_encryption_interface_init));

static int
open_device (DroidianEncryptionServiceEncryption *self,
             const char                          *header_path)
{
  g_return_val_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_ENCRYPTION (self), -1);

  return crypt_init (&self->crypt_device, header_path);
}

static int
get_supported_features (void)
{
  int flags = 0;
  struct dm_task *dmt = NULL;
  struct dm_versions *target;
  struct dm_versions *last_target;

  if (!(dmt = dm_task_create (DM_DEVICE_LIST_VERSIONS)))
      goto out;

  if (!(dm_task_run (dmt)))
      goto out;

  target = dm_task_get_versions (dmt);

  do
    {
      last_target = target;

      if (strcmp ("crypt", target->name) == 0)
        {
          if (target->version[0] >= 1 && target->version[1] >= 17)
            {
              /* sector_size supported */
              flags |= DM_CRYPT_SECTOR_SIZE;
            }
        }

      target = (void *) target + target->next;
    }
  while (last_target != target);

out:
  if (dmt)
      dm_task_destroy (dmt);

  return flags;
}

static gpointer
start_encryption (DroidianEncryptionServiceEncryption *self)
{
  DroidianEncryptionServiceDbusEncryption *dbus_encryption = DROIDIAN_ENCRYPTION_SERVICE_DBUS_ENCRYPTION (self);
  g_autofree char* header_device = NULL;
  g_autofree char* data_device = NULL;
  g_autofree char* cipher = NULL;
  g_autofree char* cipher_mode = NULL;
  DroidianEncryptionServiceEncryptionStatus encryption_status;
  struct crypt_params_luks2 luks2_params;
  struct crypt_params_reencrypt params;
  int result;

  g_return_val_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_ENCRYPTION (self), NULL);
  g_return_val_if_fail (DROIDIAN_ENCRYPTION_SERVICE_DBUS_IS_ENCRYPTION (dbus_encryption), NULL);

  g_mutex_lock (&self->encryption_process_mutex);

  header_device = droidian_encryption_service_config_get_header_device (self->config);
  data_device = droidian_encryption_service_config_get_data_device (self->config);
  cipher = droidian_encryption_service_config_get_cipher (self->config);
  cipher_mode = droidian_encryption_service_config_get_cipher_mode (self->config);

  luks2_params = (struct crypt_params_luks2) {
    .data_device = data_device,
  };

  params = (struct crypt_params_reencrypt) {
    .resilience = "checksum",
    .hash = "sha256",
    .direction = CRYPT_REENCRYPT_FORWARD,
    .mode = CRYPT_REENCRYPT_ENCRYPT,
    .flags = CRYPT_REENCRYPT_INITIALIZE_ONLY,
    .luks2 = &luks2_params,
  };

  if (!self->crypt_device && (result = open_device (self, header_device)) < 0)
      goto out;

  /* Set offset */
  if ((result = crypt_set_data_offset (self->crypt_device, 0)) < 0)
      goto out;

  /* Set sector_size, ensure we keep supporting older kernels */
  if (droidian_encryption_service_config_get_sector_size_force (self->config) ||
      get_supported_features () & DM_CRYPT_SECTOR_SIZE)
    {
      /* Use the user specified sector_size (default is 4096) */
      luks2_params.sector_size = droidian_encryption_service_config_get_sector_size (self->config);
    }
  else
    {
      /* Unable to get flags, or sector_size not supported */
      g_warning ("Sector size is not supported by the running kernel, fallbacking to 512");
      luks2_params.sector_size = 512;
    }


  /* Format header */
  if ((result = crypt_format (self->crypt_device, CRYPT_LUKS2, cipher,
                             cipher_mode, NULL, NULL, 512 / 8, &luks2_params)) < 0)
      goto out;

  /* Create volume key */
  if ((result = crypt_keyslot_add_by_volume_key (self->crypt_device, CRYPT_ANY_SLOT, NULL,
                                                0, self->passphrase, strlen (self->passphrase))) < 0)
      goto out;

  if ((result = crypt_reencrypt_init_by_passphrase (self->crypt_device, NULL,
                                                   self->passphrase, strlen (self->passphrase),
                                                   CRYPT_ANY_SLOT, 0,
                                                   cipher, cipher_mode,
                                                   &params)) < 0)
      goto out;

  g_debug ("Encryption finished");

out:
  if (result < 0)
    {
      g_warning ("Unable to start encryption: %s", g_strerror (result * -1));
      encryption_status = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_FAILED;
    }
  else
    {
      encryption_status = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_CONFIGURED;
    }

  droidian_encryption_service_dbus_encryption_set_status (dbus_encryption,
                                                          (int) encryption_status);
  g_free (self->passphrase);
  self->passphrase = NULL;
  g_mutex_unlock (&self->encryption_process_mutex);

  return NULL;
}

static gboolean
handle_start (DroidianEncryptionServiceDbusEncryption *dbus_encryption,
              GDBusMethodInvocation                   *invocation,
              const char                              *passphrase)
{
  DroidianEncryptionServiceEncryption *self = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION (dbus_encryption);
  DroidianEncryptionServiceEncryptionStatus encryption_status;

  g_mutex_lock (&self->encryption_process_mutex);

  encryption_status = droidian_encryption_service_dbus_encryption_get_status (dbus_encryption);
  if (encryption_status != DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_UNCONFIGURED)
    /* TODO: return a GError instead */
    goto out;

  droidian_encryption_service_dbus_encryption_set_status (dbus_encryption,
                                                          (int) DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_CONFIGURING);

  /* Store passphrase */
  self->passphrase = g_strdup (passphrase);

  /* Prepare thread */
  self->encryption_process_thread = g_thread_new ("encryption_thread", (GThreadFunc) start_encryption, self);

out:
  g_mutex_unlock (&self->encryption_process_mutex);
  g_dbus_method_invocation_return_value (invocation, NULL);

  return TRUE;
}

static gboolean
handle_refresh_status (DroidianEncryptionServiceDbusEncryption *dbus_encryption,
                       GDBusMethodInvocation                   *invocation)
{
  DroidianEncryptionServiceEncryption *self = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION (dbus_encryption);
  DroidianEncryptionServiceEncryptionStatus encryption_status;
  crypt_status_info cryptsetup_crypt_status;
  crypt_reencrypt_info cryptsetup_reencrypt_status;
  g_autofree char *header_name = NULL;
  g_autofree char *data_name = NULL;
  g_autofree char *mapped_name = NULL;

  g_return_val_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_ENCRYPTION (self), FALSE);

  /* Set default encryption status to the last one */
  encryption_status = droidian_encryption_service_dbus_encryption_get_status (dbus_encryption);

  if (!g_mutex_trylock (&self->encryption_process_mutex))
      /* Operation ongoing or configuring/configured, return last cached status */
      goto out;

  /* Set default encryption status to the last one */
  encryption_status = (DroidianEncryptionServiceEncryptionStatus)
    droidian_encryption_service_dbus_encryption_get_status (dbus_encryption);

  if (encryption_status == DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_CONFIGURING ||
      encryption_status == DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_CONFIGURED ||
      encryption_status == DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_UNSUPPORTED ||
      encryption_status == DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_FAILED)

      /* Configuring/configured/unsupported/failed, return last cached status */
      goto cleanup;

  if (access (DROIDIAN_ENCRYPTION_HELPER_PIDFILE, F_OK) == 0)
    {
      /* Helper pidfile exists, assume we're in the configuring state */
      encryption_status = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_ENCRYPTING;
      goto save;
    }

  if (access (DROIDIAN_ENCRYPTION_HELPER_FAILURE, F_OK) == 0)
    {
      /* Failure flag found, signal that */
      encryption_status = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_FAILED;
      goto save;
    }

  header_name = droidian_encryption_service_config_get_header_device (self->config);
  data_name = droidian_encryption_service_config_get_data_device (self->config);
  mapped_name = droidian_encryption_service_config_get_mapped_name (self->config);

  if (access (header_name, F_OK) != 0 || access (data_name, F_OK) != 0)
    {
      encryption_status = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_UNSUPPORTED;
      goto save;
    }
  
  if (!self->crypt_device && open_device (self, header_name) < 0)
      goto cleanup;

  cryptsetup_crypt_status = crypt_status (self->crypt_device, mapped_name);

  switch (cryptsetup_crypt_status)
    {
    case CRYPT_INVALID:
    case CRYPT_INACTIVE:
      /* Unconfigured */
      encryption_status = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_UNCONFIGURED;
      goto save;

    case CRYPT_ACTIVE:
    case CRYPT_BUSY:
      /* Continue checking */
      g_debug ("Found active or busy encrypted device");
      break;

    default:
      g_warning ("Unknown status %d returned by libcryptsetup", cryptsetup_crypt_status);
      goto cleanup;
    }

  /* If we are here, continue checking for clues... */

  cryptsetup_reencrypt_status = crypt_reencrypt_status (self->crypt_device, NULL);

  switch (cryptsetup_reencrypt_status)
    {
    case CRYPT_REENCRYPT_NONE:
      /* Re-encrypt has finished. Device is fully encrypted */
      encryption_status = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_ENCRYPTED;
      break;

    case CRYPT_REENCRYPT_CLEAN:
      /* No errors, but re-encryption is still ongoing */
      encryption_status = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_ENCRYPTING;
      break;

    default:
      /* Something wrong happened */
      encryption_status = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_FAILED;
      break;
    }

save:
  droidian_encryption_service_dbus_encryption_set_status (dbus_encryption,
                                                          (int) encryption_status);

cleanup:
  g_mutex_unlock (&self->encryption_process_mutex);

out:
  g_dbus_method_invocation_return_value (invocation, NULL);

  return TRUE;
}

static gboolean
on_authorize_method (GDBusInterfaceSkeleton *skeleton,
                     GDBusMethodInvocation  *invocation,
                     gpointer                user_data)
{
  DroidianEncryptionServiceEncryption *self = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION (skeleton);
  g_autoptr (PolkitSubject) subject = NULL;
  g_autoptr (PolkitAuthorizationResult) authorization_result = NULL;
  g_autoptr (GError) error = NULL;
  const char *sender, *method_name, *action = NULL;
  gboolean authorized = FALSE;

  g_return_val_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_ENCRYPTION (self), FALSE);

  /* If no authority is available, bail out */
  g_return_val_if_fail (POLKIT_IS_AUTHORITY (self->authority), FALSE);

  /* Register timestamp */
  droidian_encryption_service_dbus_register_timestamp (self->dbus);

  /* Check for authorization */
  sender = g_dbus_method_invocation_get_sender (invocation); /* owned by the invocation */
  method_name = g_dbus_method_invocation_get_method_name (invocation); /* owned by the invocation */
  subject = polkit_system_bus_name_new (sender);

  if (g_strcmp0 (method_name, "Start") == 0)
    {
      /* Start encryption */
      action = "org.droidian.EncryptionService.EncryptionStart";
    }
  else if (g_strcmp0 (method_name, "RefreshStatus") == 0)
    {
      /* Refresh status, no authorization required */
      authorized = TRUE;
    }
  else
    {
      g_warning ("Unknown method %s", method_name);
    }

  if (action)
    {
      authorization_result =
        polkit_authority_check_authorization_sync (self->authority,
                                                   subject, action,
                                                   NULL,
                                                   POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
                                                   NULL, &error);

      if (!authorization_result)
        {
          g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                                 "Authorization error: %s", error->message);
          goto out;
        }
      else
        {
          authorized = polkit_authorization_result_get_is_authorized (authorization_result);
        }
    }

  if (!authorized)
    {
      g_dbus_method_invocation_return_error (invocation, POLKIT_ERROR, POLKIT_ERROR_NOT_AUTHORIZED,
                                            "Not authorized");
    }

out:
  return authorized;
}

static void
on_dbus_bus_acquired (DroidianEncryptionServiceEncryption *self,
                      GDBusConnection   *connection,
                      DroidianEncryptionServiceDbus        *dbus)
{
  g_autoptr (GError) error = NULL;

  g_return_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_ENCRYPTION (self));
  g_return_if_fail (G_IS_DBUS_CONNECTION (connection));
  g_return_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_DBUS (dbus));

  g_signal_connect (self, "g-authorize-method", G_CALLBACK (on_authorize_method), NULL);

  if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (self),
                                        connection,
                                        "/Encryption",
                                        &error))
    {
      g_warning ("Unable to export Encryption DBus interface: %s", error->message);
      self->interface_exported = FALSE;
    }
  else
    {
      self->interface_exported = TRUE;
    }
}

DroidianEncryptionServiceEncryptionStatus
droidian_encryption_service_encryption_get_last_status (DroidianEncryptionServiceEncryption *self)
{
  DroidianEncryptionServiceDbusEncryption *dbus_encryption = DROIDIAN_ENCRYPTION_SERVICE_DBUS_ENCRYPTION (self);

  g_return_val_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_ENCRYPTION (self), DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_FAILED);
  g_return_val_if_fail (DROIDIAN_ENCRYPTION_SERVICE_DBUS_IS_ENCRYPTION (dbus_encryption), DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_FAILED);

  return (DroidianEncryptionServiceEncryptionStatus)
    droidian_encryption_service_dbus_encryption_get_status (dbus_encryption);
}

static void
droidian_encryption_service_encryption_constructed (GObject *obj)
{
  DroidianEncryptionServiceEncryption *self = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION (obj);
  g_autoptr (GError) error = NULL;

  G_OBJECT_CLASS (droidian_encryption_service_encryption_parent_class)->constructed (obj);

  self->dbus = droidian_encryption_service_dbus_get_default ();
  self->config = droidian_encryption_service_config_get_default ();
  self->interface_exported = FALSE;
  self->authority = NULL;
  self->encryption_process_thread = NULL;
  self->crypt_device = NULL;
  self->passphrase = NULL;

  g_mutex_init (&self->encryption_process_mutex);

  /* Get polkit authority */
  self->authority = polkit_authority_get_sync (NULL, &error);
  if (error != NULL)
    {
      g_printerr ("Error while getting polkit authority: %s\n", error->message);
    }

  g_signal_connect_object (self->dbus, "bus-acquired",
                           G_CALLBACK (on_dbus_bus_acquired),
                           self, G_CONNECT_SWAPPED);

}

static void
droidian_encryption_service_encryption_dispose (GObject *obj)
{
  DroidianEncryptionServiceEncryption *self = DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION (obj);

  g_debug ("Encryption dispose");

  if (self->encryption_process_thread)
    g_thread_join (self->encryption_process_thread);

  if (g_dbus_interface_skeleton_get_object_path (G_DBUS_INTERFACE_SKELETON (self)))
      g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (self));

  if (self->crypt_device)
      crypt_free (self->crypt_device);

  g_mutex_clear (&self->encryption_process_mutex);

  g_free (self->passphrase);
  self->passphrase = NULL;

  g_object_unref (self->authority);
  g_object_unref (self->dbus);
  g_object_unref (self->config);

  G_OBJECT_CLASS (droidian_encryption_service_encryption_parent_class)->dispose (obj);
}

static void
droidian_encryption_service_encryption_class_init (DroidianEncryptionServiceEncryptionClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = droidian_encryption_service_encryption_constructed;
  object_class->dispose = droidian_encryption_service_encryption_dispose;
}

static void
droidian_encryption_service_dbus_encryption_interface_init (DroidianEncryptionServiceDbusEncryptionIface *iface)
{
  iface->handle_start  = handle_start;
  iface->handle_refresh_status = handle_refresh_status;
}

static void
droidian_encryption_service_encryption_init (DroidianEncryptionServiceEncryption *self)
{
  (void) self;
}

DroidianEncryptionServiceEncryption *
droidian_encryption_service_encryption_get_default (void)
{
  static DroidianEncryptionServiceEncryption *instance = NULL;
  static GMutex mutex;

  g_mutex_lock (&mutex);

  if (instance == NULL)
    {
      instance = g_object_new (DROIDIAN_ENCRYPTION_SERVICE_TYPE_ENCRYPTION, NULL);
      g_object_add_weak_pointer (G_OBJECT (instance), (gpointer) &instance);
    }
  else
    {
      g_object_ref (instance);
    }

  g_mutex_unlock (&mutex);

  return instance;
}

