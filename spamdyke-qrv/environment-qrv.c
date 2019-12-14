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
#include <string.h>
#include "spamdyke-qrv.h"
#include "log-qrv.h"
#include "environment-qrv.h"

/*
 * Return value:
 *   SUCCESS: pointer to value of target_variable within the environment array (not copied)
 *   FAILURE: NULL
 */
char *find_environment_variable(struct qrv_settings *current_settings, char **environment, char *target_variable, int strlen_target_variable)
  {
  char *return_value;
  int i;

  return_value = NULL;

  if ((environment != NULL) &&
      (target_variable != NULL))
    for (i = 0; environment[i] != NULL; i++)
      if ((strncmp(environment[i], target_variable, strlen_target_variable) == 0) &&
          (environment[i][strlen_target_variable] == ENVIRONMENT_DELIMITER))
        {
        return_value = environment[i] + strlen_target_variable + 1;
        QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_ENVIRONMENT_FOUND, strlen_target_variable, target_variable, return_value);

        break;
        }

  return(return_value);
  }
