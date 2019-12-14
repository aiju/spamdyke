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
#include <unistd.h>
#include <string.h>
#include "spamdyke-qrv.h"
#include "configuration-qrv.h"
#include "environment-qrv.h"
#include "validate-qrv.h"
#include "log-qrv.h"

int main(int argc, char *argv[], char *arge[])
  {
  int return_value;
  struct qrv_settings tmp_settings;
  struct qrv_settings *current_settings;

  return_value = DECISION_UNKNOWN;
  current_settings = &tmp_settings;

  init_settings(current_settings, arge);
  if (!process_command_line(current_settings, argc, argv))
    {
    if (geteuid() != 0)
      QRV_LOG_VERBOSE(current_settings, LOG_VERBOSE_NOT_ROOT, geteuid());

    if ((current_settings->relayclient = find_environment_variable(current_settings, arge, ENVIRONMENT_RELAYCLIENT, STRLEN(ENVIRONMENT_RELAYCLIENT))) == NULL)
      QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_RELAYCLIENT_NONE, NULL);

    if ((current_settings->path = find_environment_variable(current_settings, arge, ENVIRONMENT_PATH, STRLEN(ENVIRONMENT_PATH))) == NULL)
      {
      QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_PATH_DEFAULT, DEFAULT_PATH);
      current_settings->path = DEFAULT_PATH;
      }

    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VERSION, VERSION_STRING);
    switch (return_value = validate(current_settings, current_settings->recipient_username, strlen(current_settings->recipient_username), current_settings->recipient_domain, NULL))
      {
      case DECISION_UNKNOWN:
        QRV_LOG_VERBOSE(current_settings, LOG_VERBOSE_UNKNOWN, NULL);
        break;
      case DECISION_VALID:
        QRV_LOG_VERBOSE(current_settings, LOG_VERBOSE_VALID, NULL);
        break;
      default:
        break;
      }
    }
  else
    return_value = DECISION_ERROR;

  if (free_settings(current_settings) != 0)
    return_value = DECISION_ERROR;

  return(return_value);
  }
