/* config.c
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

#define G_LOG_DOMAIN "droidian-encryption-service-config"

#define CONFIGURATION_FILE "/etc/droidian-encryption-service.conf"
#define CONFIGURATION_FILE_SECTION "droidian-encryption-service"

#define DEFAULT_HEADER "/dev/droidian/droidian-reserved"
#define DEFAULT_DATA "/dev/droidian/droidian-rootfs"
#define DEFAULT_NAME "droidian_encrypted"
#define DEFAULT_CIPHER "aes"
#define DEFAULT_CIPHER_MODE "xts-plain64"

#define CREATE_CONFIG_GET_STRING(KEY, DEFAULT) \
  char * \
  droidian_encryption_service_config_get_##KEY (DroidianEncryptionServiceConfig *self) \
  { \
    g_autoptr(GError) error = NULL; \
    char *result_string = droidian_encryption_service_config_get_string (self, CONFIGURATION_FILE_SECTION, \
                                                                         #KEY, &error); \
    if (error != NULL) { \
      g_printerr ("Unable to get key " #KEY ": %s\n", error->message); \
      result_string = g_strdup (DEFAULT); \
    } \
    return result_string; \
  }


#include "config.h"

struct _DroidianEncryptionServiceConfig
{
  GObject parent_instance;

  GKeyFile *key_file;
};

G_DEFINE_TYPE (DroidianEncryptionServiceConfig, droidian_encryption_service_config, G_TYPE_OBJECT)

static char *
droidian_encryption_service_config_get_string (DroidianEncryptionServiceConfig *self,
                                               const char                      *section,
                                               const char                      *key,
                                               GError                         **error)
{
  if (!DROIDIAN_ENCRYPTION_SERVICE_IS_CONFIG (self))
    /* Programmer error */
    g_error ("DROIDIAN_ENCRYPTION_SERVICE_IS_CONFIG() failed");

  return g_key_file_get_string (self->key_file, section, key, error);
}

CREATE_CONFIG_GET_STRING (header_device, DEFAULT_HEADER);
CREATE_CONFIG_GET_STRING (data_device, DEFAULT_DATA);
CREATE_CONFIG_GET_STRING (mapped_name, DEFAULT_NAME);
CREATE_CONFIG_GET_STRING (cipher, DEFAULT_CIPHER);
CREATE_CONFIG_GET_STRING (cipher_mode, DEFAULT_CIPHER_MODE);

static void
droidian_encryption_service_config_constructed (GObject *obj)
{
  DroidianEncryptionServiceConfig *self = DROIDIAN_ENCRYPTION_SERVICE_CONFIG (obj);
  g_autoptr(GError) error = NULL;

  G_OBJECT_CLASS (droidian_encryption_service_config_parent_class)->constructed (obj);

  self->key_file = g_key_file_new ();

  if (!g_key_file_load_from_file (self->key_file, CONFIGURATION_FILE, G_KEY_FILE_NONE, &error))
      g_printerr ("Unable to read configuration file %s: %s\n",
                  CONFIGURATION_FILE, error->message);

}

static void
droidian_encryption_service_config_dispose (GObject *obj)
{
  DroidianEncryptionServiceConfig *self = DROIDIAN_ENCRYPTION_SERVICE_CONFIG (obj);

  g_debug ("Config dispose");

  G_OBJECT_CLASS (droidian_encryption_service_config_parent_class)->dispose (obj);

  g_clear_object (&self->key_file);
}

static void
droidian_encryption_service_config_class_init (DroidianEncryptionServiceConfigClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->constructed  = droidian_encryption_service_config_constructed;
  object_class->dispose      = droidian_encryption_service_config_dispose;
}

static void
droidian_encryption_service_config_init (DroidianEncryptionServiceConfig *self)
{
  (void) self;
}

DroidianEncryptionServiceConfig *
droidian_encryption_service_config_get_default (void)
{
  static DroidianEncryptionServiceConfig *instance = NULL;
  static GMutex mutex;

  g_mutex_lock (&mutex);

  if (instance == NULL)
    {
      instance = g_object_new (DROIDIAN_ENCRYPTION_SERVICE_TYPE_CONFIG, NULL);
      g_object_add_weak_pointer (G_OBJECT (instance), (gpointer) &instance);
    }
  else
    {
      g_object_ref (instance);
    }

  g_mutex_unlock (&mutex);

  return instance;
}

