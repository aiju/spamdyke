/*
  spamdyke -- a filter for stopping spam at connection time.
  Copyright (C) 2015 Sam Clippinger (samc (at) silence (dot) org)

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config-qrv.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_GETOPT_H

#define _GNU_SOURCE
#include <getopt.h>

#else /* HAVE_GETOPT_H */

#include <unistd.h>

#endif /* HAVE_GETOPT_H */

#include "spamdyke-qrv.h"
#include "configuration-qrv.h"
#include "usage-qrv.h"
#include "array-qrv.h"
#include "log-qrv.h"

/*
 * RETURN VALUE:
 *   0 = success
 *   -1 = error
 */
int init_settings(struct qrv_settings *current_settings, char **environment)
  {
  if (current_settings != NULL)
    {
    current_settings->verbose = 0;
    current_settings->diag = 0;

    current_settings->qmail_percenthack_file = NULL;
    current_settings->qmail_locals_file = NULL;
    current_settings->qmail_virtualdomains_file = NULL;
    current_settings->qmail_assign_cdb = NULL;
    current_settings->qmail_rcpthosts_file = NULL;
    current_settings->qmail_morercpthosts_cdb = NULL;

    current_settings->qmail_defaultdelivery_file = NULL;
    current_settings->qmail_envnoathost_file = NULL;
    current_settings->qmail_me_file = NULL;
    current_settings->recipient_domain = NULL;
    current_settings->recipient_username = NULL;
    current_settings->relayclient = NULL;
    current_settings->path = NULL;

    current_settings->environment = environment;
    }

  return(0);
  }

/*
 * RETURN VALUE:
 *   0 = success
 *   -1 = error
 */
int free_settings(struct qrv_settings *current_settings)
  {
  int return_value;

  return_value = 0;

  if (current_settings != NULL)
    {
    if ((array_free(&current_settings->qmail_percenthack_file) != 0) ||
        (array_free(&current_settings->qmail_locals_file) != 0) ||
        (array_free(&current_settings->qmail_virtualdomains_file) != 0) ||
        (array_free(&current_settings->qmail_assign_cdb) != 0) ||
        (array_free(&current_settings->qmail_rcpthosts_file) != 0) ||
        (array_free(&current_settings->qmail_morercpthosts_cdb) != 0))
      return_value = -1;
    }

  return(return_value);
  }

/*
 * RETURN VALUE:
 *   0 = success
 *   -1 = error
 */
int process_command_line(struct qrv_settings *current_settings, int argc, char *argv[])
  {
  int return_value;
  int tmp_opt;
  int usage_printed;
  struct option option_list[] = {
    { "help",                           no_argument,            NULL,   'h' },
    { "verbose",                        no_argument,            NULL,   'v' },
    { "diag",                           no_argument,            NULL,   'd' },
    { "qmail-percenthack-file",         required_argument,      NULL,   258 },
    { "qmail-locals-file",              required_argument,      NULL,   259 },
    { "qmail-virtualdomains-file",      required_argument,      NULL,   260 },
    { "qmail-assign-cdb",               required_argument,      NULL,   261 },
    { "qmail-defaultdelivery-file",     required_argument,      NULL,   262 },
    { "qmail-envnoathost-file",         required_argument,      NULL,   263 },
    { "qmail-me-file",                  required_argument,      NULL,   264 },
    { "qmail-rcpthosts-file",           required_argument,      NULL,   265 },
    { "qmail-morercpthosts-cdb",        required_argument,      NULL,   266 },
    { 0, 0, 0, 0 }
    };

  return_value = 0;
  opterr = 0;
  usage_printed = 0;

  if (current_settings != NULL)
    {
    while ((return_value == 0) &&
           ((tmp_opt = getopt_long(argc, argv, "hdv", option_list, NULL)) != -1))
      switch (tmp_opt)
        {
        case 'h':
          usage(0);
          exit(DECISION_UNKNOWN);

          break;
        case 'v':
          current_settings->verbose++;
          break;
        case 'd':
          current_settings->diag++;
          break;
        case 258:
          if (array_append(&current_settings->qmail_percenthack_file, optarg) == -1)
            return_value = -1;

          break;
        case 259:
          if (array_append(&current_settings->qmail_locals_file, optarg) == -1)
            return_value = -1;

          break;
        case 260:
          if (array_append(&current_settings->qmail_virtualdomains_file, optarg) == -1)
            return_value = -1;

          break;
        case 261:
          if (array_append(&current_settings->qmail_assign_cdb, optarg) == -1)
            return_value = -1;

          break;
        case 262:
          current_settings->qmail_defaultdelivery_file = optarg;
          break;
        case 263:
          current_settings->qmail_envnoathost_file = optarg;
          break;
        case 264:
          current_settings->qmail_me_file = optarg;
          break;
        case 265:
          if (array_append(&current_settings->qmail_rcpthosts_file, optarg) == -1)
            return_value = -1;

          break;
        case 266:
          if (array_append(&current_settings->qmail_morercpthosts_cdb, optarg) == -1)
            return_value = -1;

          break;
        default:
          if (!usage_printed)
            {
            usage(1);
            usage_printed = 1;
            }

          QRV_LOG_ERROR(current_settings, LOG_ERROR_OPTION_UNKNOWN, argv[optind]);
          return_value = -1;

          break;
        }

    if (return_value != -1)
      {
      if (optind < argc)
        current_settings->recipient_domain = argv[optind];
      else
        {
        if (!usage_printed)
          {
          usage(1);
          usage_printed = 1;
          }

        QRV_LOG_ERROR(current_settings, LOG_ERROR_OPTION_MISSING_DOMAIN, NULL);
        return_value = -1;
        }

      if ((optind + 1) < argc)
        current_settings->recipient_username = argv[optind + 1];
      else
        {
        if (!usage_printed)
          {
          usage(1);
          usage_printed = 1;
          }

        QRV_LOG_ERROR(current_settings, LOG_ERROR_OPTION_MISSING_USERNAME, NULL);
        return_value = -1;
        }
      }

#ifdef WITH_VPOPMAIL_SUPPORT

    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_VALIAS, VPOPMAIL_VALIAS_PATH);
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_VUSERINFO, VPOPMAIL_VUSERINFO_PATH);

#endif /* WITH_VPOPMAIL_SUPPORT */

    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "qmail_percenthack_file", array_join(current_settings->qmail_percenthack_file, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "qmail_locals_file", array_join(current_settings->qmail_locals_file, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "qmail_virtualdomains_file", array_join(current_settings->qmail_virtualdomains_file, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "qmail_assign_cdb", array_join(current_settings->qmail_assign_cdb, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "qmail_rcpthosts_file", array_join(current_settings->qmail_rcpthosts_file, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "qmail_morercpthosts_cdb", array_join(current_settings->qmail_morercpthosts_cdb, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "qmail_defaultdelivery_file", (current_settings->qmail_defaultdelivery_file != NULL) ? current_settings->qmail_defaultdelivery_file : LOG_DATA_NULL);
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "qmail_envnoathost_file", (current_settings->qmail_envnoathost_file != NULL) ? current_settings->qmail_envnoathost_file : LOG_DATA_NULL);
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "qmail_me_file", (current_settings->qmail_me_file != NULL) ? current_settings->qmail_me_file : LOG_DATA_NULL);
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "recipient_domain", (current_settings->recipient_domain != NULL) ? current_settings->recipient_domain : LOG_DATA_NULL);
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_GIVEN, "recipient_username", (current_settings->recipient_username != NULL) ? current_settings->recipient_username : LOG_DATA_NULL);

    if ((return_value != -1) &&
        (current_settings->qmail_percenthack_file == NULL) &&
        (array_append(&current_settings->qmail_percenthack_file, DEFAULT_QMAIL_PERCENTHACK_FILE) == -1))
      return_value = -1;

    if ((return_value != -1) &&
        (current_settings->qmail_locals_file == NULL) &&
        (array_append(&current_settings->qmail_locals_file, DEFAULT_QMAIL_LOCALS_FILE) == -1))
      return_value = -1;

    if ((return_value != -1) &&
        (current_settings->qmail_virtualdomains_file == NULL) &&
        (array_append(&current_settings->qmail_virtualdomains_file, DEFAULT_QMAIL_VIRTUALDOMAINS_FILE) == -1))
      return_value = -1;

    if ((return_value != -1) &&
        (current_settings->qmail_assign_cdb == NULL) &&
        (array_append(&current_settings->qmail_assign_cdb, DEFAULT_QMAIL_ASSIGN_CDB) == -1))
      return_value = -1;

    if ((return_value != -1) &&
        (current_settings->qmail_rcpthosts_file == NULL) &&
        (array_append(&current_settings->qmail_rcpthosts_file, DEFAULT_QMAIL_RCPTHOSTS_FILE) == -1))
      return_value = -1;

    if ((return_value != -1) &&
        (current_settings->qmail_morercpthosts_cdb == NULL) &&
        (array_append(&current_settings->qmail_morercpthosts_cdb, DEFAULT_QMAIL_MORERCPTHOSTS_CDB) == -1))
      return_value = -1;

    if ((return_value != -1) &&
        (current_settings->qmail_defaultdelivery_file == NULL))
      current_settings->qmail_defaultdelivery_file = DEFAULT_QMAIL_DEFAULTDELIVERY_FILE;

    if ((return_value != -1) &&
        (current_settings->qmail_envnoathost_file == NULL))
      current_settings->qmail_envnoathost_file = DEFAULT_QMAIL_ENVNOATHOST_FILE;

    if ((return_value != -1) &&
        (current_settings->qmail_me_file == NULL))
      current_settings->qmail_me_file = DEFAULT_QMAIL_ME_FILE;

    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "qmail_percenthack_file", array_join(current_settings->qmail_percenthack_file, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "qmail_locals_file", array_join(current_settings->qmail_locals_file, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "qmail_virtualdomains_file", array_join(current_settings->qmail_virtualdomains_file, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "qmail_assign_cdb", array_join(current_settings->qmail_assign_cdb, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "qmail_rcpthosts_file", array_join(current_settings->qmail_rcpthosts_file, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "qmail_morercpthosts_cdb", array_join(current_settings->qmail_morercpthosts_cdb, ", ", LOG_DATA_NULL));
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "qmail_defaultdelivery_file", (current_settings->qmail_defaultdelivery_file != NULL) ? current_settings->qmail_defaultdelivery_file : LOG_DATA_NULL);
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "qmail_envnoathost_file", (current_settings->qmail_envnoathost_file != NULL) ? current_settings->qmail_envnoathost_file : LOG_DATA_NULL);
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "qmail_me_file", (current_settings->qmail_me_file != NULL) ? current_settings->qmail_me_file : LOG_DATA_NULL);
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "recipient_domain", (current_settings->recipient_domain != NULL) ? current_settings->recipient_domain : LOG_DATA_NULL);
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPTIONS_SET, "recipient_username", (current_settings->recipient_username != NULL) ? current_settings->recipient_username : LOG_DATA_NULL);
    }
  else
    return_value = -1;

  return(return_value);
  }
