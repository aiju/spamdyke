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
#include "config-qrv.h"
#include "spamdyke-qrv.h"
#include "array-qrv.h"

/*
 * RETURN VALUE:
 *   0 = success
 *   -1 = error
 */
int array_append(char ***target_array, char *new_value)
  {
  int return_value;
  int tmp_len;
  char **new_array;

  return_value = -1;

  if (target_array != NULL)
    {
    if ((*target_array) != NULL)
      for (tmp_len = 0; (*target_array)[tmp_len] != NULL; tmp_len++);
    else
      tmp_len = 0;

    if ((new_array = realloc((*target_array), sizeof(char *) * (tmp_len + 2))) != NULL)
      {
      new_array[tmp_len] = new_value;
      new_array[tmp_len + 1] = NULL;

      *target_array = new_array;

      return_value = 0;
      }
    }

  return(return_value);
  }

/*
 * RETURN VALUE:
 *   0 = success
 *   -1 = error
 */
int array_free(char ***target_array)
  {
  if ((target_array != NULL) &&
      ((*target_array) != NULL))
    {
    free((*target_array));
    *target_array = NULL;
    }

  return(0);
  }

/*
 * RETURN VALUE:
 *   !NULL = target_array contained data that was printed to static buffer
 *   null_return = target_array contained no non-NULL data
 */
char *array_join(char **target_array, char *delimiter, char *null_return)
  {
  static char tmp_buf[MAX_BUF + 1];
  char *return_value;
  int i;
  int tmp_strlen;
  int cur_strlen;

  cur_strlen = 0;
  return_value = null_return;
  tmp_buf[0] = '\0';

  if (delimiter != NULL)
    {
    if ((target_array != NULL) &&
        (target_array[0] != NULL))
      {
      cur_strlen = SNPRINTF(tmp_buf, MAX_BUF, "%s", target_array[0]);

      for (i = 1; (target_array[i] != NULL) && (cur_strlen < MAX_BUF); i++)
        {
        tmp_strlen = SNPRINTF(tmp_buf + cur_strlen, MAX_BUF - cur_strlen, "%s%s", delimiter, target_array[i]);
        cur_strlen += tmp_strlen;
        }

      tmp_buf[cur_strlen] = '\0';
      return_value = tmp_buf;
      }
    }

  return(return_value);
  }
