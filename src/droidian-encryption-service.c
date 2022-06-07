/* main.c
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

#include <glib.h>
#include <stdlib.h>

#include "dbus.h"
#include "encryption.h"

static gboolean should_quit = FALSE;

static gboolean
handle_unix_signal (void)
{
  g_warning ("Asked to exit...");

  should_quit = TRUE;
  g_main_context_wakeup (NULL);

  return G_SOURCE_REMOVE;
}

static void
handle_timeout_reached (DroidianEncryptionServiceDbus *dbus)
{
  DroidianEncryptionServiceEncryption *encryption;

  g_return_if_fail (DROIDIAN_ENCRYPTION_SERVICE_IS_DBUS (dbus));

  g_debug ("Idle timeout reached");

  /* Safety check for CONFIGURING / CONFIGURED status (where the service must not exit) */
  encryption = droidian_encryption_service_encryption_get_default ();

  switch (droidian_encryption_service_encryption_get_last_status (encryption))
    {
    case DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_CONFIGURING:
    case DROIDIAN_ENCRYPTION_SERVICE_ENCRYPTION_STATUS_CONFIGURED:
      g_warning ("Service will remain in background due to configuring/configured status");
      break;

    default:
      should_quit = TRUE;
      g_main_context_wakeup (NULL);
      break;
    }
}

gint
main (gint   argc,
      gchar *argv[])
{
  g_autoptr(GOptionContext) context = NULL;
  g_autoptr(GError) error = NULL;
  gboolean version = FALSE;
  GOptionEntry main_entries[] = {
    { "version", 0, 0, G_OPTION_ARG_NONE, &version, "Show program version", NULL },
    { NULL }
  };

  context = g_option_context_new ("- encryption service");
  g_option_context_add_main_entries (context, main_entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_printerr ("%s\n", error->message);
      return EXIT_FAILURE;
    }

  if (version)
    {
      g_printerr ("%s\n", PACKAGE_VERSION);
      return EXIT_SUCCESS;
    }

  DroidianEncryptionServiceDbus *dbus = droidian_encryption_service_dbus_get_default ();
  DroidianEncryptionServiceEncryption *encryption =
    droidian_encryption_service_encryption_get_default ();

  droidian_encryption_service_dbus_own_name (dbus);

  GMainContext *main_context = g_main_context_default ();

  g_unix_signal_add (SIGTERM, G_SOURCE_FUNC (handle_unix_signal), NULL);
  g_signal_connect (dbus, "timeout-reached", G_CALLBACK (handle_timeout_reached), NULL);

  while (!should_quit)
    g_main_context_iteration (main_context, TRUE);

  /* Cleanup */
  g_object_unref (encryption);
  g_object_unref (dbus);

  return EXIT_SUCCESS;
}
