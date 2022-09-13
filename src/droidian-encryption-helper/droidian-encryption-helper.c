/* droidian-encryption-helper.c
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

#define _GNU_SOURCE

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <libcryptsetup.h>

/* TODO: Remove GLib dependency - it's already half way done */

#define PASSPHRASE_MAX 256

#define RUN_DIR "/run"
#define HALIUM_MOUNTED_STAMP_NAME "halium-mounted"
#define HALIUM_MOUNTED_STAMP RUN_DIR "/" HALIUM_MOUNTED_STAMP_NAME
#define DROIDIAN_ENCRYPTION_HELPER_PIDFILE_NAME "droidian-encryption-helper.pid"
#define DROIDIAN_ENCRYPTION_HELPER_PIDFILE RUN_DIR "/" DROIDIAN_ENCRYPTION_HELPER_PIDFILE_NAME
#define DROIDIAN_ENCRYPTION_HELPER_FAILURE_NAME "droidian-encryption-helper-failed"
#define DROIDIAN_ENCRYPTION_HELPER_FAILURE RUN_DIR "/" DROIDIAN_ENCRYPTION_HELPER_FAILURE_NAME
#define DROIDIAN_BOOT_DONE_STAMP_NAME "boot-done"
#define DROIDIAN_BOOT_DONE_STAMP RUN_DIR "/" DROIDIAN_BOOT_DONE_STAMP_NAME

typedef enum {
  DROIDIAN_ENCRYPTION_HELPER_MISSING_ARGUMENTS,
  DROIDIAN_ENCRYPTION_HELPER_FAILED_TO_READ_PASSPHRASE,
  DROIDIAN_ENCRYPTION_HELPER_FAILED_TO_INIT,
  DROIDIAN_ENCRYPTION_HELPER_FAILED_TO_LOAD,
  DROIDIAN_ENCRYPTION_HELPER_FAILED_TO_LOAD_HEADER,
  DROIDIAN_ENCRYPTION_HELPER_FAILED_TO_ACTIVATE,
  DROIDIAN_ENCRYPTION_HELPER_FAILED_REENCRYPTION,
  DROIDIAN_ENCRYPTION_HELPER_FAILED_REENCRYPTION_RUN,
  DROIDIAN_ENCRYPTION_HELPER_FAILED_REGISTER_TERMINATION_HANDLERS,
} DroidianEncryptionHelperError;


G_DEFINE_QUARK (droidian-encryption-helper-error-quark, droidian_encryption_helper_error);
#define DROIDIAN_ENCRYPTION_HELPER_ERROR (droidian_encryption_helper_error_quark())

#define EXIT_UNABLE_TO_ACTIVATE 2

static gboolean teardown = FALSE;

gint
report_reencryption_status (uint64_t size, uint64_t offset, void *data)
{
  /* Silence warnings */
  (void) size;
  (void) offset;
  (void) data;

  /* TODO: Add a way to show progress */
  return teardown ? 1 : 0;
}

gboolean
start_reencryption (struct crypt_device *crypt_device,
                    const char          *name,
                    char                *passphrase,
                    GError             **error)
{
  gint result;
  struct crypt_params_reencrypt params = {
    .resilience = "checksum",
    .hash = "sha256",
    .flags = CRYPT_REENCRYPT_RESUME_ONLY,
  };

  result = crypt_reencrypt_init_by_passphrase (crypt_device, name,
                                               passphrase, strlen (passphrase),
                                               CRYPT_ANY_SLOT, 0, /* TODO: make this configurable */
                                               NULL, NULL, &params);

  if (result < 0)
      goto error;

  result = crypt_reencrypt_run (crypt_device, report_reencryption_status, NULL);
  if (result < 0)
      goto error;

  return TRUE;

error:
  g_set_error (error, DROIDIAN_ENCRYPTION_HELPER_ERROR,
               DROIDIAN_ENCRYPTION_HELPER_FAILED_REENCRYPTION_RUN,
               "Unable to start reencryption on %s: %s",
               crypt_get_device_name (crypt_device),
               g_strerror (-result));
  return FALSE;
}

gboolean
needs_reencryption (struct crypt_device *crypt_device,
                    GError             **error)
{
  gboolean should_reencrypt;
  crypt_reencrypt_info status = crypt_reencrypt_status (crypt_device, NULL);

  switch (status)
    {
    case CRYPT_REENCRYPT_NONE:
      should_reencrypt = FALSE;
      break;

    case CRYPT_REENCRYPT_CLEAN:
      should_reencrypt = TRUE;
      break;

    default:
      g_set_error (error, DROIDIAN_ENCRYPTION_HELPER_ERROR,
                   DROIDIAN_ENCRYPTION_HELPER_FAILED_REENCRYPTION,
                   "libcryptsetup reported reencryption failure on %s: %d",
                   crypt_get_device_name (crypt_device), status);
      should_reencrypt = TRUE;
      break;
    }

  return should_reencrypt;
}


gboolean
activate (struct crypt_device *crypt_device,
          const char          *name,
          const char          *passphrase,
          GError             **error)
{
  gint result;

  result = crypt_load (crypt_device, CRYPT_LUKS2, NULL);
  if (result < 0)
    {
      g_set_error (error, DROIDIAN_ENCRYPTION_HELPER_ERROR,
                   DROIDIAN_ENCRYPTION_HELPER_FAILED_TO_LOAD,
                   "Unable to crypto_load() on device %s: %s",
                   crypt_get_device_name (crypt_device),
                   g_strerror (-result));
      return FALSE;
    }

  /* Finally activate */
  result = crypt_activate_by_passphrase (crypt_device, name, CRYPT_ANY_SLOT,
                                         passphrase, strlen (passphrase), 0);
  if (result < 0)
    {
      g_set_error (error, DROIDIAN_ENCRYPTION_HELPER_ERROR,
                   DROIDIAN_ENCRYPTION_HELPER_FAILED_TO_ACTIVATE,
                   "Unable to activate device %s: %s",
                   crypt_get_device_name (crypt_device),
                   g_strerror (-result));
      return FALSE;
    }

  return TRUE;
}

static void
handle_signal (const int signal)
{
  switch (signal)
    {
    case SIGINT:
    case SIGTERM:
      teardown = TRUE;
      break;

    default:
      g_warning ("Unknown signal %i", signal);
      break;
    }
}

static gboolean
register_signals (GError **error)
{
  gint result;
  struct sigaction action = {
    .sa_handler = handle_signal,
    .sa_flags = 0,
  };
  sigemptyset (&action.sa_mask);

  result = sigaction (SIGINT, &action, NULL);
  if (result < 0)
      goto error;

  result = sigaction (SIGTERM, &action, NULL);
  if (result < 0)
      goto error;

  return TRUE;

error:
  g_set_error (error, DROIDIAN_ENCRYPTION_HELPER_ERROR,
               DROIDIAN_ENCRYPTION_HELPER_FAILED_REGISTER_TERMINATION_HANDLERS,
               "Unable to register termination handlers");
  return FALSE;
}

gint
main (gint   argc,
      gchar *argv[])
{
  gint result;
  gint exit_code = EXIT_SUCCESS;
  struct crypt_device *crypt_device = NULL;
  g_autoptr(GOptionContext) context = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree char *device = NULL;
  g_autofree char *header = NULL;
  g_autofree char *rootmnt = NULL;
  g_autofree char *target_name = NULL;
  g_autofree char *passphrase = NULL;
  g_autofree char *pid = NULL;
  gboolean strip_newlines = FALSE;
  gboolean version = FALSE;
  gboolean should_reencrypt;
  int length;
  int ch;
  int i;
  int run_fd = -1;
  pid_t child = -1;

  GOptionEntry main_entries[] = {
    { "device", 0, 0, G_OPTION_ARG_FILENAME, &device, "Device to open", NULL },
    { "header", 0, 0, G_OPTION_ARG_FILENAME, &header, "Detached header to use", NULL },
    { "rootmnt", 0, 0, G_OPTION_ARG_FILENAME, &rootmnt, "Root mountpoint", NULL },
    { "name", 0, 0, G_OPTION_ARG_STRING, &target_name, "Name to use", NULL },
    { "strip-newlines", 0, 0, G_OPTION_ARG_NONE, &strip_newlines, "Strip newlines", NULL },
    { "version", 0, 0, G_OPTION_ARG_NONE, &version, "Show program version", NULL },
    { NULL }
  };

  context = g_option_context_new ("- helper for droidian-encryption-daemon");
  g_option_context_add_main_entries (context, main_entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      goto out;
    }

  if (version)
    {
      g_printerr ("%s\n", PACKAGE_VERSION);
      goto out;
    }
  
  if (!device || !header || !target_name)
    {
      g_set_error (&error, DROIDIAN_ENCRYPTION_HELPER_ERROR,
                   DROIDIAN_ENCRYPTION_HELPER_MISSING_ARGUMENTS,
                   "Missing required arguments (--device, --header, --name)");
      goto out;
    }

  /* Read passphrase from stdin */
  passphrase = g_malloc0 (PASSPHRASE_MAX);
  i = 0;
  while ((ch = fgetc (stdin)) != EOF)
    {
      if (i < PASSPHRASE_MAX && (strip_newlines && ch != '\n'))
        {
          passphrase[i++] = ch;
        }
      else if (i >= PASSPHRASE_MAX)
        {
          g_warning ("PASSPHRASE_MAX reached");
          break;
        }
    }

  if (!i)
    {
      g_set_error (&error, DROIDIAN_ENCRYPTION_HELPER_ERROR,
                   DROIDIAN_ENCRYPTION_HELPER_FAILED_TO_READ_PASSPHRASE,
                   "Unable to read passphrase");
      exit_code = EXIT_UNABLE_TO_ACTIVATE; /* Unable to activate */
      goto out;
    }

  result = crypt_init_data_device (&crypt_device, header, device);
  if (result < 0)
    {
      g_set_error (&error, DROIDIAN_ENCRYPTION_HELPER_ERROR,
                   DROIDIAN_ENCRYPTION_HELPER_FAILED_TO_INIT,
                   "Unable to init context: %s",
                   g_strerror (-result));
      goto out;
    }

  /* Activate */
  error = NULL;
  if (!activate (crypt_device, target_name, passphrase, &error)) {
      exit_code = EXIT_UNABLE_TO_ACTIVATE; /* Unable to activate */
      goto out;
  }

  /* Should reencryption be started? */
  error = NULL;
  should_reencrypt = needs_reencryption (crypt_device, &error);
  if (error != NULL || !should_reencrypt)
      /* Error, or device already encrypted */
      goto out;

  /* Continue by starting the re-encryption process. */
  if ((run_fd = open("/run", O_PATH)) == -1)
    {
      g_printerr ("Unable to open /run\n");
      goto out;
    }

  error = NULL;
  child = fork();
  if (child == -1)
    {
      g_printerr ("Unable to fork()\n");
      goto out;
    }
  else if (child == 0)
    {
      /* Ensure systemd doesn't kill us before running switch_root: https://systemd.io/ROOT_STORAGE_DAEMONS/ */
      argv[0][0] = '@';

      /* Register signals */
      if (!register_signals (&error))
          goto out;

      /* Wait for the move to happen if rootmnt has been specified */
      if (rootmnt)
        {
          while (!teardown && faccessat (run_fd, HALIUM_MOUNTED_STAMP_NAME, F_OK, 0) == -1)
            {
              g_printerr ("Root move stamp not found, waiting: errno %d, teardown %d\n", errno, teardown);
              sleep (1);
            }

          if (teardown)
              goto out;

          /* If we're here, the mounted stamp has been touched - so we can chroot to the new root mountpoint */
          chroot (rootmnt);

          /* ..and finally remove the stamp file */
          if (unlinkat (run_fd, HALIUM_MOUNTED_STAMP_NAME, 0) == -1)
            {
              g_printerr ("Unable to remove halium mounted stamp\n");
              goto out;
            }
        }

      /* Wait for the boot to complete */
      while (!teardown && faccessat (run_fd, DROIDIAN_BOOT_DONE_STAMP_NAME, F_OK, 0) == -1)
        {
          g_printerr ("Boot done stamp not found, waiting: errno %d, teardown %d\n", errno, teardown);
          sleep (10);
        }

      if (teardown || !start_reencryption (crypt_device, target_name, passphrase, &error))
          goto out;

      g_warning ("Reencrypt finished!");
    }
  else
    {
      /* Write the child pid to the pidfile */
      length = snprintf ( NULL, 0, "%d", child) + 1;
      pid = g_malloc (length);
      snprintf (pid, length, "%d",  child);
      g_file_set_contents (DROIDIAN_ENCRYPTION_HELPER_PIDFILE, pid, -1, &error);
    }


out:
  if (error)
    {
      g_printerr ("%s\n", error->message);

      if (exit_code == EXIT_SUCCESS)
          exit_code = EXIT_FAILURE;

      if (child == 0)
          /* Create failure stamp file */
          g_file_set_contents (DROIDIAN_ENCRYPTION_HELPER_FAILURE, error->message, -1, &error);
    }

  if (child == 0 && faccessat (run_fd, DROIDIAN_ENCRYPTION_HELPER_PIDFILE_NAME, F_OK, 0) == 0)
    {
      /* Unlink pid file */
      if (unlinkat (run_fd, DROIDIAN_ENCRYPTION_HELPER_PIDFILE_NAME, 0) == -1)
        {
            g_printerr ("Unable to unlink pidfile\n");
            exit_code = EXIT_FAILURE;
        }
    }

  if (crypt_device)
      crypt_free (crypt_device);

  if (run_fd > -1)
      close (run_fd);

  return exit_code;
}
