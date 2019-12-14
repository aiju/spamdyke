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
#include <stdarg.h>
#include "spamdyke-qrv.h"
#include "log-qrv.h"

void log_qrv(char *format, ...)
  {
  va_list tmp_va_list;

  va_start(tmp_va_list, format);
  vprintf(format, tmp_va_list);
  printf("\n");
  va_end(tmp_va_list);

  return;
  }

char *escape_log_text(char *target_text, int strlen_target_text)
  {
  static char return_value[MAX_BUF + 1];
  int i;
  int strlen_return;

  strlen_return = 0;

  if (target_text != NULL)
    for (i = 0; (i < strlen_target_text) && (strlen_return < (MAX_BUF - 1)); i++)
      {
      if (target_text[i] == '\0')
        {
        return_value[strlen_return] = '\\';
        strlen_return++;
        return_value[strlen_return] = '0';
        }
      else if (target_text[i] == '\r')
        {
        return_value[strlen_return] = '\\';
        strlen_return++;
        return_value[strlen_return] = 'r';
        }
      else if (target_text[i] == '\n')
        {
        return_value[strlen_return] = '\\';
        strlen_return++;
        return_value[strlen_return] = 'n';
        }
      else if (target_text[i] == '\t')
        {
        return_value[strlen_return] = '\\';
        strlen_return++;
        return_value[strlen_return] = 't';
        }
      else if (target_text[i] == '\\')
        {
        return_value[strlen_return] = '\\';
        strlen_return++;
        return_value[strlen_return] = '\\';
        }
      else
        return_value[strlen_return] = target_text[i];

      strlen_return++;
      }

  return_value[strlen_return] = '\0';

  return(return_value);
  }
