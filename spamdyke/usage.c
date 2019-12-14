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
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include "spamdyke.h"
#include "configuration.h"
#include "usage.h"

void print_help_text(char *input_text, int indent_level)
  {
  int i;
  int strlen_text;
  int cur_loc;
  int next_loc;

  if (input_text != NULL)
    {
    strlen_text = strlen(input_text);
    for (cur_loc = 0; (cur_loc < strlen_text) && (input_text[cur_loc] == ' '); cur_loc++);

    while (cur_loc < strlen_text)
      {
      if ((strlen_text - cur_loc) > USAGE_LINE_WRAP)
        {
        for (next_loc = cur_loc + (USAGE_LINE_WRAP - (STRLEN(USAGE_LINE_INDENT) * indent_level)) + 1; (next_loc > cur_loc) && (input_text[next_loc] != ' '); next_loc--);
        if (next_loc == cur_loc)
          for (next_loc = cur_loc + (USAGE_LINE_WRAP - (STRLEN(USAGE_LINE_INDENT) * indent_level)) + 1; (next_loc < strlen_text) && (input_text[next_loc] != ' '); next_loc++);
        }
      else
        next_loc = strlen_text;

      for (i = 0; i < indent_level; i++)
        fprintf(stderr, USAGE_LINE_INDENT);
      fprintf(stderr, "%.*s\n", next_loc - cur_loc, input_text + cur_loc);

      for (cur_loc = next_loc + 1; (cur_loc < strlen_text) && (input_text[cur_loc] == ' '); cur_loc++);
      }
    }

  return;
  }

void usage(struct filter_settings *current_settings, int text_level, char *error_pattern, ...)
  {
  static int banner_printed = 0;
  int i;
  int j;
  va_list tmp_va;
  char usage_text[MAX_BUF + 1];
  char values_text[MAX_BUF + 1];
  int strlen_values_text;

  if (!banner_printed)
    {
    fprintf(stderr, USAGE_MESSAGE_HEADER);

    if (text_level == USAGE_LEVEL_SHORT)
      fprintf(stderr, USAGE_MESSAGE_FOOTER_SHORT);

    banner_printed = 1;
    }

  if (error_pattern != NULL)
    {
    va_start(tmp_va, error_pattern);
    vfprintf(stderr, error_pattern, tmp_va);
    va_end(tmp_va);
    }
  else if ((text_level == USAGE_LEVEL_BRIEF) ||
           (text_level == USAGE_LEVEL_LONG))
    {
    fprintf(stderr, USAGE_MESSAGE_USAGE);
    fprintf(stderr, "\n");

    for (i = 0; current_settings->option_list[i].value_type != CONFIG_TYPE_NONE; i++)
      if (current_settings->option_list[i].help_text != NULL)
        {
        values_text[0] = '\0';
        if (((current_settings->option_list[i].value_type == CONFIG_TYPE_NAME_ONCE) ||
             (current_settings->option_list[i].value_type == CONFIG_TYPE_NAME_MULTIPLE)) &&
            (current_settings->option_list[i].validity.string_list.strings[0] != NULL))
          {
          strlen_values_text = SNPRINTF(values_text, MAX_BUF, "%s", current_settings->option_list[i].validity.string_list.strings[0]);
          for (j = 1; current_settings->option_list[i].validity.string_list.strings[j] != NULL; j++)
            {
            snprintf(values_text + strlen_values_text, MAX_BUF - strlen_values_text, USAGE_MESSAGE_NAME_VALUE_DELIMITER "%s", current_settings->option_list[i].validity.string_list.strings[j]);
            strlen_values_text += strlen(values_text + strlen_values_text);
            }
          }

        if (current_settings->option_list[i].getopt_option.val <= current_settings->max_short_code)
          {
          if ((current_settings->option_list[i].getopt_option.has_arg == optional_argument) &&
              (current_settings->option_list[i].help_argument != NULL))
            if (values_text[0] != '\0')
              {
              snprintf(usage_text, MAX_BUF, "-%c[ %s ]", current_settings->option_list[i].getopt_option.val, values_text);
              print_help_text(usage_text, 0);
              }
            else
              fprintf(stderr, "-%c[%s]\n", current_settings->option_list[i].getopt_option.val, current_settings->option_list[i].help_argument);
          else if ((current_settings->option_list[i].getopt_option.has_arg == required_argument) &&
                   (current_settings->option_list[i].help_argument != NULL))
            if (values_text[0] != '\0')
              {
              snprintf(usage_text, MAX_BUF, "-%c { %s }", current_settings->option_list[i].getopt_option.val, values_text);
              print_help_text(usage_text, 0);
              }
            else
              fprintf(stderr, "-%c %s\n", current_settings->option_list[i].getopt_option.val, current_settings->option_list[i].help_argument);
          else
            fprintf(stderr, "-%c\n", current_settings->option_list[i].getopt_option.val);
          }

        if (current_settings->option_list[i].getopt_option.name != NULL)
          {
          if ((current_settings->option_list[i].getopt_option.has_arg == optional_argument) &&
              (current_settings->option_list[i].help_argument != NULL))
            if (values_text[0] != '\0')
              {
              snprintf(usage_text, MAX_BUF, "--%s=[ %s ]", current_settings->option_list[i].getopt_option.name, values_text);
              print_help_text(usage_text, 0);
              }
            else
              fprintf(stderr, "--%s=[%s]\n", current_settings->option_list[i].getopt_option.name, current_settings->option_list[i].help_argument);
          else if ((current_settings->option_list[i].getopt_option.has_arg == required_argument) &&
                   (current_settings->option_list[i].help_argument != NULL))
            if (values_text[0] != '\0')
              {
              snprintf(usage_text, MAX_BUF, "--%s { %s }", current_settings->option_list[i].getopt_option.name, values_text);
              print_help_text(usage_text, 0);
              }
            else
              fprintf(stderr, "--%s %s\n", current_settings->option_list[i].getopt_option.name, current_settings->option_list[i].help_argument);
          else
            fprintf(stderr, "--%s\n", current_settings->option_list[i].getopt_option.name);
          }

        if (text_level == USAGE_LEVEL_LONG)
          {
          print_help_text(current_settings->option_list[i].help_text, 1);

          if (current_settings->option_list[i].help_argument != NULL)
            {
            if (current_settings->option_list[i].value_type == CONFIG_TYPE_INTEGER)
              fprintf(stderr, USAGE_LINE_INDENT USAGE_MESSAGE_INTEGER_RANGE, current_settings->option_list[i].help_argument, current_settings->option_list[i].validity.integer_range.minimum, current_settings->option_list[i].validity.integer_range.maximum);

            if (current_settings->option_list[i].getopt_option.has_arg == optional_argument)
              {
              if (current_settings->option_list[i].getopt_option.val <= current_settings->max_short_code)
                fprintf(stderr, USAGE_LINE_INDENT USAGE_MESSAGE_OPTIONAL_SHORT, current_settings->option_list[i].getopt_option.val, current_settings->option_list[i].help_argument);

              if (current_settings->option_list[i].getopt_option.name != NULL)
                fprintf(stderr, USAGE_LINE_INDENT USAGE_MESSAGE_OPTIONAL_LONG, current_settings->option_list[i].getopt_option.name, current_settings->option_list[i].help_argument);
              }
            }

          switch (current_settings->option_list[i].value_type)
            {
            case CONFIG_TYPE_STRING_ARRAY:
            case CONFIG_TYPE_FILE_ARRAY:
            case CONFIG_TYPE_FILE_NOT_DIR_ARRAY:
            case CONFIG_TYPE_DIR_ARRAY:
            case CONFIG_TYPE_COMMAND_ARRAY:
            case CONFIG_TYPE_OPTION_ARRAY:
            case CONFIG_TYPE_ACTION_MULTIPLE:
            case CONFIG_TYPE_NAME_MULTIPLE:
              fprintf(stderr, USAGE_LINE_INDENT USAGE_MESSAGE_ARRAY, current_settings->option_list[i].getopt_option.name);
              break;
            case CONFIG_TYPE_INTEGER:
            case CONFIG_TYPE_STRING_SINGLETON:
            case CONFIG_TYPE_FILE_SINGLETON:
            case CONFIG_TYPE_FILE_NOT_DIR_SINGLETON:
            case CONFIG_TYPE_DIR_SINGLETON:
            case CONFIG_TYPE_COMMAND_SINGLETON:
            case CONFIG_TYPE_OPTION_SINGLETON:
            case CONFIG_TYPE_ACTION_ONCE:
            case CONFIG_TYPE_NAME_ONCE:
              fprintf(stderr, USAGE_LINE_INDENT USAGE_MESSAGE_SINGLETON, current_settings->option_list[i].getopt_option.name);
              break;
            default:
              break;
            }

          fprintf(stderr, "\n");
          }
        }

    if (text_level == USAGE_LEVEL_LONG)
      fprintf(stderr, USAGE_MESSAGE_FOOTER_LONG);
    else
      fprintf(stderr, USAGE_MESSAGE_FOOTER_BRIEF);
    }

  return;
  }
