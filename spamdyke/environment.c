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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spamdyke.h"
#include "log.h"
#include "environment.h"

/*
 * Return value:
 *   SUCCESS: pointer to value of target_variable within the environment array (not copied)
 *   FAILURE: NULL
 */
char *find_environment_variable(struct filter_settings *current_settings, char **environment, char *target_variable, int strlen_target_variable, int *return_index)
  {
  char *return_value;
  int i;

  return_value = NULL;

  if (environment != NULL)
    for (i = 0; environment[i] != NULL; i++)
      if ((strncmp(environment[i], target_variable, strlen_target_variable) == 0) &&
          (environment[i][strlen_target_variable] == ENVIRONMENT_DELIMITER))
        {
        if (return_index != NULL)
          *return_index = i;

        return_value = environment[i] + strlen_target_variable + 1;
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_ENVIRONMENT_FOUND, strlen_target_variable, target_variable, return_value);
        break;
        }

  return(return_value);
  }

void free_environment(char **original_envp, char ***target_envp, char **new_envp)
  {
  int i;
  int j;
  int found_match;

  if ((original_envp != NULL) &&
      (target_envp != NULL) &&
      ((*target_envp) != NULL) &&
      (original_envp != (*target_envp)))
    {
    for (i = 0; (*target_envp)[i] != NULL; i++)
      {
      found_match = 0;

      for (j = 0; original_envp[j] != NULL; j++)
        if ((*target_envp)[i] == original_envp[j])
          {
          found_match = 1;
          break;
          }

      if ((original_envp[j] == NULL) &&
          (new_envp != NULL))
        for (j = 0; new_envp[j] != NULL; j++)
          if ((*target_envp)[i] == new_envp[j])
            {
            found_match = 1;
            break;
            }

      if (!found_match)
        free((*target_envp)[i]);
      }

    free(*target_envp);
    *target_envp = NULL;
    }

  return;
  }

void free_environment_variable(char **original_envp, char ***target_envp, int target_index)
  {
  int len_target;
  int i;
  int found_match;

  if ((original_envp != NULL) &&
      (target_envp != NULL) &&
      ((*target_envp) != NULL) &&
      (target_index >= 0) &&
      ((*target_envp)[target_index] != NULL))
    {
    found_match = 0;

    for (len_target = 0; (*target_envp)[len_target] != NULL; len_target++);
    for (i = 0; original_envp[i] != NULL; i++)
      if (original_envp[i] == (*target_envp)[target_index])
        {
        found_match = 1;
        break;
        }

    if (!found_match)
      free((*target_envp)[target_index]);

    (*target_envp)[target_index] = (*target_envp)[len_target - 1];
    (*target_envp)[len_target] = NULL;
    }

  return;
  }

char *alloc_environment_variable(char **original_envp, char *target_variable, int new_size)
  {
  int i;
  int found_match;

  found_match = 0;

  if ((original_envp != NULL) &&
      (target_variable != NULL))
    for (i = 0; original_envp[i] != NULL; i++)
      if (target_variable == original_envp[i])
        {
        found_match = 1;
        break;
        }

  return(found_match ? malloc(new_size) : realloc(target_variable, new_size));
  }

void print_current_environment(struct filter_settings *current_settings)
  {
  int i;
  int tmp_strlen;
  char tmp_buf[MAX_BUF + 1];

  if ((current_settings->current_options->log_dir != NULL) &&
      (current_settings->current_environment != NULL))
    for (i = 0; current_settings->current_environment[i] != NULL; i++)
      {
      tmp_strlen = SNPRINTF(tmp_buf, MAX_BUF, "%s\n", current_settings->current_environment[i]);
      output_writeln(current_settings, LOG_ACTION_CURRENT_ENVIRONMENT, -1, tmp_buf, tmp_strlen);
      }

  return;
  }
