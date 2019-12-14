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
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fnmatch.h>
#include <unistd.h>
#include "spamdyke.h"
#include "environment.h"
#include "log.h"
#include "configuration.h"
#include "search_fs.h"

/*
 * strlen_target_path may be -1 if target_path is nul-terminated.
 *
 * Return value:
 *   destination_buf
 */
char *canonicalize_path(char *destination_buf, int maxlen_destination_buf, char *target_path, int strlen_target_path)
  {
  char *filename_alphabet = ALPHABET_FILENAME;
  int i;

  i = 0;

  if ((destination_buf != NULL) &&
      (maxlen_destination_buf > 0))
    {
    if (target_path != NULL)
      for (i = 0; ((i < maxlen_destination_buf) && (((strlen_target_path >= 0) && (i < strlen_target_path)) || ((strlen_target_path == -1) && (target_path[i] != '\0')))); i++)
        destination_buf[i] = (strchr(filename_alphabet, target_path[i]) != NULL) ? tolower((int)target_path[i]) : REPLACEMENT_FILENAME;

    destination_buf[i] = '\0';
    }

  return(destination_buf);
  }

/*
 * Return value:
 *   NOT FOUND: 0
 *   FOUND: 1
 */
int find_path(struct filter_settings *current_settings, char *filename, char *envp[], char *return_filename, int size_return_filename)
  {
  int return_value;
  int strlen_filename;
  char *path;
  char *tmp_start;
  char *tmp_end;
  char new_filename[MAX_BUF + 1];
  struct stat tmp_stat;

  return_value = 0;

  if ((filename != NULL) &&
      (return_filename != NULL) &&
      (size_return_filename > 0))
    {
    if (stat(filename, &tmp_stat) == 0)
      {
      strlen_filename = MINVAL(size_return_filename, strlen(filename));
      memcpy(return_filename, filename, sizeof(char) * strlen_filename);
      return_filename[strlen_filename] = '\0';

      return_value = 1;
      }
    else if (strchr(filename, DIR_DELIMITER) == NULL)
      {
      if (((path = find_environment_variable(current_settings, envp, ENVIRONMENT_PATH, STRLEN(ENVIRONMENT_PATH), NULL)) == NULL) ||
          (path[0] == '\0'))
        {
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_PATH_DEFAULT, DEFAULT_PATH);
        path = DEFAULT_PATH;
        }

      tmp_start = path;
      tmp_end = NULL;
      while (tmp_start != NULL)
        {
        if ((tmp_end = strchr(tmp_start, ENVIRONMENT_DELIMITER)) != NULL)
          {
          strlen_filename = SNPRINTF(new_filename, MAX_BUF, "%.*s" DIR_DELIMITER_STR "%s", (int)(tmp_end - tmp_start), tmp_start, filename);
          tmp_start = tmp_end + 1;
          }
        else
          {
          strlen_filename = SNPRINTF(new_filename, MAX_BUF, "%s" DIR_DELIMITER_STR "%s", tmp_start, filename);
          tmp_start = NULL;
          }

        if (stat(new_filename, &tmp_stat) == 0)
          {
          if (strlen_filename > size_return_filename)
            strlen_filename = size_return_filename;

          memcpy(return_filename, new_filename, sizeof(char) * strlen_filename);
          return_filename[strlen_filename] = '\0';

          return_value = 1;
          break;
          }
        }
      }
    }

  return(return_value);
  }

/*
 * When passed an entire command line string (e.g. from a .qmail file), this
 * function finds just the command itself, allowing for escaping characters
 * and quoting.
 *
 * RETURNS:
 *   characters copied to return_text
 */
int find_command(char *input_text, char *return_text, int size_return_text)
  {
  int return_value;
  int i;
  int escape;
  int inside_quote;

  return_value = 0;
  escape = 0;
  inside_quote = 0;

  if ((input_text != NULL) &&
      (return_text != NULL))
    {
    for (i = 0; input_text[i] != '\0'; i++)
      if (!isspace((int)input_text[i]))
        break;

    for (; (input_text[i] != '\0') && (return_value < size_return_text); i++)
      if (isspace((int)input_text[i]) &&
          !inside_quote &&
          !escape)
        break;
      else if (escape)
        {
        return_text[return_value] = input_text[i];
        return_value++;
        escape = 0;
        }
      else if (input_text[i] == PATH_ESCAPE_CHAR)
        escape = 1;
      else if (input_text[i] == PATH_QUOTE_CHAR)
        inside_quote = !inside_quote;
      else
        {
        return_text[return_value] = input_text[i];
        return_value++;
        }

    return_text[return_value] = '\0';
    }

  return(return_value);
  }

/*
 * Return value:
 *   NULL: no match
 *   pointer to match within haystack: match
 */
char *find_case_insensitive_needle(char *haystack, char *needle)
  {
  char *return_value;
  int i;
  char tmp_buf[MAX_BUF + 1];

  if ((haystack != NULL) &&
      (needle != NULL))
    {
    for (i = 0; (i < MAX_BUF) && (needle[i] != '\0'); i++)
      tmp_buf[i] = tolower((int)needle[i]);
    tmp_buf[i] = '\0';

    return_value = strstr(haystack, tmp_buf);
    }
  else
    return_value = NULL;

  return(return_value);
  }

/*
 * EXPECTS:
 *   target_string = string content to search for, must not be NULL or zero length
 *   strlen_target_string = length of target_string
 *   target_entry = string content to search within, must not be NULL
 *   strlen_target_entry = length of target_entry
 *   start_wildcard = wildcard character that, if present as the first character in target_string, allows target_string to match in the middle of target_entry.  \0 disables this feature.
 *   start_wildcard_matches = if start_wildcard matches the first character in target_string, a match is not found unless the character in target_entry immediately preceding the location is found
 *     within start_wildcard_matches.  E.g. start_wildcard is '.', target_string is ".foo" and target_entry is "bar-foo-baz".  A match is found if start_wildcard_matches is "-!#" but not if it is
 *     "/.,".  NULL disables this feature.
 *   end_wildcard = like start_wildcard but at the end of target_string instead of the start
 *   end_wildcard_matches = like start_wildcard_matches but at the end of target_string instead of the start
 *
 * Return value:
 *   0: no match
 *   1: match found
 */
int examine_entry(char *target_string, int strlen_target_string, char *target_entry, int strlen_target_entry, char start_wildcard, char *start_wildcard_matches, char end_wildcard, char *end_wildcard_matches)
  {
  int return_value;
  int check_start;
  int check_end;
  char *tmp_string;
  char old_end_char;
  char *tmp_entry;

  return_value = 0;
  check_start = 0;
  check_end = 0;

  if ((target_entry != NULL) &&
      (strlen_target_entry > 0))
    {
    old_end_char = target_entry[strlen_target_entry - 1];
    if ((end_wildcard != '\0') &&
        (target_entry[strlen_target_entry - 1] == end_wildcard))
      {
      strlen_target_entry--;
      target_entry[strlen_target_entry] = '\0';
      check_end = 1;
      }

    if ((start_wildcard != '\0') &&
        (target_entry[0] == start_wildcard))
      {
      strlen_target_entry--;
      tmp_entry = target_entry + 1;
      check_start = 1;
      }
    else
      tmp_entry = target_entry;

    tmp_string = find_case_insensitive_needle(target_string, tmp_entry);

    while ((tmp_string != NULL) &&
           (return_value == 0))
      if (((check_start &&
            ((start_wildcard_matches == NULL) ||
             (tmp_string == target_string) ||
             (strchr(start_wildcard_matches, (tmp_string - 1)[0]) != NULL))) ||
           (!check_start &&
            (tmp_string == target_string))) &&
          ((check_end &&
            ((end_wildcard_matches == NULL) ||
             (strchr(end_wildcard_matches, tmp_string[strlen_target_entry]) != NULL))) ||
           (!check_end &&
            (((tmp_string - target_string) + strlen_target_entry) == strlen_target_string))))
        return_value = 1;
      else
        tmp_string = find_case_insensitive_needle(tmp_string + 1, tmp_entry);

    strlen_target_entry += check_end + check_start;
    target_entry[strlen_target_entry - 1] = old_end_char;
    }

  return(return_value);
  }

/*
 * EXPECTS:
 *   search_filename = the file to search, line by line
 *   target_string = string content to search for, must not be NULL or zero length
 *   strlen_target_string = length of target_string
 *   start_wildcard = wildcard character that, if present as the first character in target_string, allows target_string to match in the middle of a line.  \0 disables this feature.
 *   start_wildcard_matches = if start_wildcard matches the first character in target_string, a match is not found unless the character in the line immediately preceding the location is found
 *     within start_wildcard_matches.  E.g. start_wildcard is '.', target_string is ".foo" and the line is "bar-foo-baz".  A match is found if start_wildcard_matches is "-!#" but not if it is
 *     "/.,".  NULL disables this feature.
 *   end_wildcard = like start_wildcard but at the end of target_string instead of the start
 *   end_wildcard_matches = like start_wildcard_matches but at the end of target_string instead of the start
 *
 * Return value:
 *   ERROR: -1
 *   NOT FOUND: 0
 *   FOUND: matching line number
 */
int search_file(struct filter_settings *current_settings, char *search_filename, char *target_string, int strlen_target_string, char start_wildcard, char *start_wildcard_matches, char end_wildcard, char *end_wildcard_matches)
  {
  int return_value;
  FILE *tmp_file;
  char tmp_buf[MAX_FILE_BUF + 1];
  int line_num;
  int i;
  int strlen_buf;
  char lower_start_wildcard;
  char lower_end_wildcard;
  char lower_target_string[MAX_BUF + 1];
  int strlen_lower_target_string;

  return_value = 0;

  if ((target_string != NULL) &&
      (strlen_target_string > 0))
    {
    if ((tmp_file = fopen(search_filename, "r")) != NULL)
      {
      line_num = 0;

      lower_start_wildcard = (start_wildcard != '\0') ? tolower((int)start_wildcard) : start_wildcard;
      lower_end_wildcard = (end_wildcard != '\0') ? tolower((int)end_wildcard) : end_wildcard;

      strlen_lower_target_string = MINVAL(MAX_BUF, strlen_target_string);
      for (i = 0; i < strlen_lower_target_string; i++)
        lower_target_string[i] = tolower((int)target_string[i]);

      while (!feof(tmp_file) &&
             (line_num < MAX_FILE_LINES))
        {
        if ((fscanf(tmp_file, "%" STRINGIFY(MAX_FILE_BUF) "[^\r\n]", tmp_buf) == 1) &&
            (tmp_buf[0] != COMMENT_DELIMITER) &&
            ((strlen_buf = strlen(tmp_buf)) > 0) &&
            examine_entry(lower_target_string, strlen_lower_target_string, tmp_buf, strlen_buf, lower_start_wildcard, start_wildcard_matches, lower_end_wildcard, end_wildcard_matches))
          {
          return_value = line_num + 1;
          break;
          }

        fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      if (line_num == MAX_FILE_LINES)
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_FILE_TOO_LONG "%s", MAX_FILE_LINES, search_filename);

      fclose(tmp_file);
      }
    else
      {
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_OPEN_SEARCH "%s: %s", search_filename, strerror(errno));
      return_value = -1;
      }
    }

  return(return_value);
  }

/*
 * Return value:
 *   0: no match
 *   1: match found
 */
int sub_examine_tcprules_entry(char *destination, int size_destination, char *env_info, int target_ip_ints[4], char *target_entry, int strlen_target_entry, char *target_name, int strlen_target_name)
  {
  int return_value;
  int j;
  int k;
  char tmp_buf[MAX_FILE_BUF + 1];
  char *loc_cmd;
  char *loc_info;
  char *loc_start;
  char *tmp_name;
  char ip_octets[4][8];
  char mask_octets[4][4];
  int ip_ints[4];
  int range_ints[4];
  int mask_ints[4];
  int sscanf_result;
  int network_size;

  return_value = 0;

  snprintf(tmp_buf, MAX_FILE_BUF, "%s", target_entry);

  if ((loc_cmd = strchr(tmp_buf, TCPRULES_ENVIRONMENT)) != NULL)
    {
    if (loc_cmd == tmp_buf)
      {
      if (destination != NULL)
        snprintf(destination, size_destination, "%s", loc_cmd + 1);

      return_value = 1;
      }
    else
      {
      loc_cmd[0] = '\0';
      loc_cmd++;
      }
    }

  if (!return_value)
    {
    if ((loc_info = strchr(tmp_buf, TCPRULES_INFO)) != NULL)
      {
      loc_info[0] = '\0';
      if ((env_info != NULL) &&
          (strcasecmp(tmp_buf, env_info) == 0))
        loc_start = loc_info + 1;
      else
        return_value = -1;
      }
    else
      loc_start = tmp_buf;
    }

  if (!return_value)
    {
    for (j = 0; j < 4; j++)
      {
      ip_octets[j][0] = '\0';
      ip_ints[j] = 0;
      range_ints[j] = -1;
      mask_octets[j][0] = '\0';
      mask_ints[j] = 0;
      }

    if (loc_start[0] == TCPRULES_NAME)
      {
      for (j = 0; tmp_buf[j] != '\0'; j++)
        tmp_buf[j] = tolower((int)tmp_buf[j]);

      if ((strlen_target_name > 0) &&
          ((loc_start[1] == '\0') ||
           (((tmp_name = find_case_insensitive_needle(target_name, loc_start + 1)) != NULL) &&
            ((tmp_name == target_name) ||
             (loc_start[1] == '.') ||
             ((tmp_name - 1)[0] == '.')))))
        {
        if (destination != NULL)
          {
          if (loc_cmd != NULL)
            snprintf(destination, size_destination, "%s", loc_cmd);
          else
            destination[0] = '\0';
          }

        return_value = 1;
        }
      }
    else if (((sscanf_result = sscanf(loc_start, "%7[0-9-].%7[0-9-].%7[0-9-].%7[0-9-]/%3[0-9].%3[0-9].%3[0-9].%3[0-9]", ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3], mask_octets[0], mask_octets[1], mask_octets[2], mask_octets[3])) > 0) &&
             (sscanf_result <= 4))
      {
      for (j = 0; j < sscanf_result; j++)
        if ((sscanf(ip_octets[j], "%3d-%3d", &ip_ints[j], &range_ints[j]) == 0) ||
            (ip_ints[j] < 0) ||
            (ip_ints[j] > 255) ||
            ((range_ints[j] == -1) &&
             (ip_ints[j] != target_ip_ints[j])) ||
            ((range_ints[j] >= ip_ints[j]) &&
             (range_ints[j] <= 255) &&
             ((ip_ints[j] > target_ip_ints[j]) ||
              (range_ints[j] < target_ip_ints[j]))))
          break;

      if (j == sscanf_result)
        {
        if (destination != NULL)
          {
          if (loc_cmd != NULL)
            snprintf(destination, size_destination, "%s", loc_cmd);
          else
            destination[0] = '\0';
          }

        return_value = 1;
        }
      }
    else if (sscanf_result == 5)
      {
      for (j = 0; j < 4; j++)
        if ((sscanf(ip_octets[j], "%3d-%3d", &ip_ints[j], &range_ints[j]) == 0) ||
            (ip_ints[j] < 0) ||
            (ip_ints[j] > 255))
          break;

      if ((j == 4) &&
          (sscanf(mask_octets[0], "%d", &network_size) == 1) &&
          (network_size >= 0) &&
          (network_size <= 32))
        {
        for (k = 0; k < network_size; k++)
          mask_ints[k / 8] |= 0x80 >> (k % 8);

        if (((mask_ints[0] & target_ip_ints[0]) == (mask_ints[0] & ip_ints[0])) &&
            ((mask_ints[1] & target_ip_ints[1]) == (mask_ints[1] & ip_ints[1])) &&
            ((mask_ints[2] & target_ip_ints[2]) == (mask_ints[2] & ip_ints[2])) &&
            ((mask_ints[3] & target_ip_ints[3]) == (mask_ints[3] & ip_ints[3])))
          return_value = 1;
        }
      }
    else if (sscanf_result == 8)
      {
      for (j = 0; j < 4; j++)
        if ((sscanf(ip_octets[j], "%3d-%d", &ip_ints[j], &range_ints[j]) == 0) ||
            (ip_ints[j] < 0) ||
            (ip_ints[j] > 255))
          break;

      if (j == 4)
        {
        for (j = 0; j < 4; j++)
          if ((sscanf(mask_octets[j], "%d", &mask_ints[j]) != 1) ||
              (mask_ints[j] < 0) ||
              (mask_ints[j] > 255))
            break;

        if ((j == 4) &&
            ((mask_ints[0] & target_ip_ints[0]) == (mask_ints[0] & ip_ints[0])) &&
            ((mask_ints[1] & target_ip_ints[1]) == (mask_ints[1] & ip_ints[1])) &&
            ((mask_ints[2] & target_ip_ints[2]) == (mask_ints[2] & ip_ints[2])) &&
            ((mask_ints[3] & target_ip_ints[3]) == (mask_ints[3] & ip_ints[3])))
          {
          if (destination != NULL)
            {
            if (loc_cmd != NULL)
              snprintf(destination, size_destination, "%s", loc_cmd);
            else
              destination[0] = '\0';
            }

          return_value = 1;
          }
        }
      }
    }

  return((return_value == 1) ? 1 : 0);
  }

/*
 * Return value:
 *   0: no match
 *   1: match found
 */
int examine_tcprules_entry(struct filter_settings *current_settings, char *destination, int size_destination, char *target_entry, int strlen_target_entry, char *target_ip, char *target_name, int strlen_target_name)
  {
  int return_value;
  char *env_info;
  char ip_octets[4][7];
  int target_ip_ints[4];

  return_value = 0;

  if ((target_ip != NULL) &&
      (sscanf(target_ip, "%3[0-9].%3[0-9].%3[0-9].%3[0-9]", ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]) == 4) &&
      (sscanf(ip_octets[0], "%d", &target_ip_ints[0]) == 1) &&
      (target_ip_ints[0] >= 0) &&
      (target_ip_ints[0] <= 255) &&
      (sscanf(ip_octets[1], "%d", &target_ip_ints[1]) == 1) &&
      (target_ip_ints[1] >= 0) &&
      (target_ip_ints[1] <= 255) &&
      (sscanf(ip_octets[2], "%d", &target_ip_ints[2]) == 1) &&
      (target_ip_ints[2] >= 0) &&
      (target_ip_ints[2] <= 255) &&
      (sscanf(ip_octets[3], "%d", &target_ip_ints[3]) == 1) &&
      (target_ip_ints[3] >= 0) &&
      (target_ip_ints[3] <= 255))
    {
    env_info = find_environment_variable(current_settings, current_settings->current_environment, ENVIRONMENT_REMOTE_INFO, STRLEN(ENVIRONMENT_REMOTE_INFO), NULL);

    return_value = sub_examine_tcprules_entry(destination, size_destination, env_info, target_ip_ints, target_entry, strlen_target_entry, target_name, strlen_target_name);
    }

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: -1
 *   NOT FOUND: 0
 *   FOUND: matching line number
 */
int search_tcprules_file(struct filter_settings *current_settings, char *destination, int size_destination, char *search_filename, char *target_ip, char *target_name, int strlen_target_name)
  {
  int return_value;
  int line_num;
  FILE *tmp_file;
  char tmp_buf[MAX_FILE_BUF + 1];
  char *env_info;
  char ip_octets[4][7];
  int target_ip_ints[4];

  return_value = 0;

  if ((target_ip != NULL) &&
      (sscanf(target_ip, "%3[0-9].%3[0-9].%3[0-9].%3[0-9]", ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]) == 4) &&
      (sscanf(ip_octets[0], "%d", &target_ip_ints[0]) == 1) &&
      (target_ip_ints[0] >= 0) &&
      (target_ip_ints[0] <= 255) &&
      (sscanf(ip_octets[1], "%d", &target_ip_ints[1]) == 1) &&
      (target_ip_ints[1] >= 0) &&
      (target_ip_ints[1] <= 255) &&
      (sscanf(ip_octets[2], "%d", &target_ip_ints[2]) == 1) &&
      (target_ip_ints[2] >= 0) &&
      (target_ip_ints[2] <= 255) &&
      (sscanf(ip_octets[3], "%d", &target_ip_ints[3]) == 1) &&
      (target_ip_ints[3] >= 0) &&
      (target_ip_ints[3] <= 255))
    {
    if ((tmp_file = fopen(search_filename, "r")) != NULL)
      {
      line_num = 0;

      env_info = find_environment_variable(current_settings, current_settings->current_environment, ENVIRONMENT_REMOTE_INFO, STRLEN(ENVIRONMENT_REMOTE_INFO), NULL);

      while (!feof(tmp_file) &&
             (line_num < MAX_FILE_LINES))
        {
        if ((fscanf(tmp_file, "%" STRINGIFY(MAX_FILE_BUF) "[^\r\n]", tmp_buf) == 1) &&
            (tmp_buf[0] != '\0') &&
            (tmp_buf[0] != COMMENT_DELIMITER) &&
            sub_examine_tcprules_entry(destination, size_destination, env_info, target_ip_ints, tmp_buf, strlen(tmp_buf), target_name, strlen_target_name))
          {
          return_value = line_num + 1;
          break;
          }

        fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      if (line_num == MAX_FILE_LINES)
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_FILE_TOO_LONG "%s", MAX_FILE_LINES, search_filename);

      fclose(tmp_file);
      }
    else
      {
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_OPEN_SEARCH "%s: %s", search_filename, strerror(errno));
      return_value = -1;
      }
    }

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int load_resolver_file(struct filter_settings *current_settings, char *search_filename, int *return_default_port)
  {
  int return_value;
  FILE *tmp_file;
  char tmp_buf[MAX_FILE_BUF + 1];
  char *search_buf;
  int line_num;
  int i;
  int orig_strlen_buf;
  int strlen_buf;
  char port[6];
  char timeout[6];
  int target_port;
  int target_timeout;
  int total_timeout;
  int query_timeout;
  int found_match;
  char ip_octets[4][4];
  int ip_ints[4];

  return_value = 1;
  total_timeout = 0;
  query_timeout = 0;

  if (search_filename != NULL)
    {
    if ((tmp_file = fopen(search_filename, "r")) != NULL)
      {
      line_num = 0;

      while (!feof(tmp_file) &&
             (line_num < MAX_FILE_LINES))
        {
        if ((fscanf(tmp_file, "%" STRINGIFY(MAX_FILE_BUF) "[^\r\n]", tmp_buf) == 1) &&
            ((orig_strlen_buf = strlen(tmp_buf)) > 0))
          {
          strlen_buf = 0;

          for (i = 0; (i < orig_strlen_buf) && isspace((int)tmp_buf[i]); i++);
          for (; (i < orig_strlen_buf) && (tmp_buf[i] != RESOLVER_FILE_COMMENT_DELIMITER_1) && (tmp_buf[i] != RESOLVER_FILE_COMMENT_DELIMITER_2); i++)
            {
            tmp_buf[strlen_buf] = tolower((int)tmp_buf[i]);
            strlen_buf++;
            }
          tmp_buf[i] = '\0';

          search_buf = tmp_buf;

          if (!strncmp(search_buf, NIHDNS_RESOLV_NAMESERVER, STRLEN(NIHDNS_RESOLV_NAMESERVER)))
            {
            for (search_buf += STRLEN(NIHDNS_RESOLV_NAMESERVER); (search_buf[0] != '\0') && isspace((int)search_buf[0]); search_buf++);

            if ((sscanf(search_buf, "%3[0-9].%3[0-9].%3[0-9].%3[0-9]", ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]) == 4) &&
                (sscanf(ip_octets[0], "%d", &ip_ints[0]) == 1) &&
                (ip_ints[0] > 0) &&
                (ip_ints[0] <= 255) &&
                (sscanf(ip_octets[1], "%d", &ip_ints[1]) == 1) &&
                (ip_ints[1] >= 0) &&
                (ip_ints[1] <= 255) &&
                (sscanf(ip_octets[2], "%d", &ip_ints[2]) == 1) &&
                (ip_ints[2] >= 0) &&
                (ip_ints[2] <= 255) &&
                (sscanf(ip_octets[3], "%d", &ip_ints[3]) == 1) &&
                (ip_ints[3] >= 0) &&
                (ip_ints[3] <= 255))
              {
              found_match = 0;
              if (current_settings->current_options->nihdns_primary_server_list != NULL)
                for (i = 0; current_settings->current_options->nihdns_primary_server_list[i] != NULL; i++)
                  if (strcmp(current_settings->current_options->nihdns_primary_server_list[i], search_buf) == 0)
                    {
                    found_match = 1;
                    break;
                    }

              if (!found_match &&
                  (current_settings->current_options->nihdns_secondary_server_list != NULL))
                for (i = 0; current_settings->current_options->nihdns_secondary_server_list[i] != NULL; i++)
                  if (strcmp(current_settings->current_options->nihdns_secondary_server_list[i], search_buf) == 0)
                    {
                    found_match = 1;
                    break;
                    }

              if (!found_match)
                {
                append_string(current_settings, ((current_settings->current_options->nihdns_primary_server_list == NULL) || (current_settings->current_options->nihdns_primary_server_list[0] == NULL)) ? &current_settings->current_options->nihdns_primary_server_list : &current_settings->current_options->nihdns_secondary_server_list, search_buf, strlen(search_buf));
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_NS_LOAD, search_filename, line_num + 1, search_buf);
                }
              else
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_NS_LOAD_DUPLICATE, search_filename, line_num + 1, search_buf);
              }
            else
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_NS_BAD, search_buf);
            }
          else if (!strncmp(search_buf, NIHDNS_RESOLV_PORT, STRLEN(NIHDNS_RESOLV_PORT)))
            {
            for (search_buf += STRLEN(NIHDNS_RESOLV_PORT); (search_buf[0] != '\0') && isspace((int)search_buf[0]); search_buf++);

            target_port = 0;
            if ((sscanf(search_buf, "%5[0-9]", port) == 1) &&
                (sscanf(port, "%d", &target_port) == 1) &&
                (target_port > 0) &&
                (target_port <= 65536))
              {
              if (return_default_port != NULL)
                *return_default_port = target_port;

              SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_PORT, search_filename, line_num + 1, target_port);
              }
            else
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_PORT_BAD, search_filename, line_num + 1, tmp_buf);
            }
          else if (!strncmp(search_buf, NIHDNS_RESOLV_TIMEOUT, STRLEN(NIHDNS_RESOLV_TIMEOUT)))
            {
            for (search_buf += STRLEN(NIHDNS_RESOLV_TIMEOUT); (search_buf[0] != '\0') && isspace((int)search_buf[0]); search_buf++);

            target_timeout = 0;
            if ((sscanf(search_buf, "%5[0-9]", timeout) == 1) &&
                (sscanf(timeout, "%d", &target_timeout) == 1) &&
                (target_timeout > 0) &&
                (target_timeout <= 65536))
              {
              total_timeout = target_timeout;

              SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_GLOBAL_TIMEOUT, search_filename, line_num + 1, total_timeout);
              }
            else
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_GLOBAL_TIMEOUT_BAD, search_filename, line_num + 1, tmp_buf);
            }
          else if (!strncmp(search_buf, NIHDNS_RESOLV_OPTIONS, STRLEN(NIHDNS_RESOLV_OPTIONS)))
            {
            while (search_buf[0] != '\0')
              {
              for (search_buf += STRLEN(NIHDNS_RESOLV_OPTIONS); (search_buf[0] != '\0') && isspace((int)search_buf[0]); search_buf++);

              if (!strncmp(search_buf, NIHDNS_RESOLV_OPTION_TIMEOUT, STRLEN(NIHDNS_RESOLV_OPTION_TIMEOUT)))
                {
                search_buf += STRLEN(NIHDNS_RESOLV_OPTION_TIMEOUT);
                target_timeout = 0;
                if ((sscanf(search_buf, "%5[0-9]", timeout) == 1) &&
                    (sscanf(timeout, "%d", &target_timeout) == 1) &&
                    (target_timeout > 0) &&
                    (target_timeout <= 65536))
                  {
                  query_timeout = target_timeout;

                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_QUERY_TIMEOUT, search_filename, line_num + 1, query_timeout);
                  }
                else
                  SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_QUERY_TIMEOUT_BAD, search_filename, line_num + 1, tmp_buf);
                }

              for (; (search_buf[0] != '\0') && !isspace((int)search_buf[0]); search_buf++);
              }
            }
          else
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_IGNORED, search_filename, line_num + 1, search_buf);
          }

        fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      if (line_num == MAX_FILE_LINES)
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_FILE_TOO_LONG "%s", MAX_FILE_LINES, search_filename);

      fclose(tmp_file);

      if ((total_timeout != 0) &&
          (current_settings->current_options->nihdns_attempts_total > 0))
        current_settings->current_options->nihdns_timeout_total_secs_system = total_timeout;
      else if (query_timeout != 0)
        current_settings->current_options->nihdns_timeout_total_secs_system = query_timeout * current_settings->current_options->nihdns_attempts_total;
      }
    else
      {
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_OPEN_SEARCH "%s: %s", search_filename, strerror(errno));
      return_value = 0;
      }
    }
  else
    return_value = 0;

  return(return_value);
  }

/*
 * Return value:
 *   NOT FOUND: NULL
 *   FOUND: pointer to static buffer containing matching path
 */
char *search_domain_directory(struct filter_settings *current_settings, char *start_directory, char *target_domain, int strlen_target_domain)
  {
  static char search_path[MAX_PATH + 1];
  char *return_value;
  int i;
  char *domain_delimiter[3];
  char *base_domain;
  struct stat tmp_stat;

  return_value = NULL;

  if ((start_directory != NULL) &&
      (start_directory[0] != '\0') &&
      (target_domain != NULL) &&
      (strlen_target_domain > 0))
    {
    domain_delimiter[0] = NULL;
    domain_delimiter[1] = NULL;
    domain_delimiter[2] = NULL;

    for (i = strlen_target_domain - 1; i >= 0; i--)
      if (target_domain[i] == '.')
        {
        if (domain_delimiter[0] == NULL)
          domain_delimiter[0] = target_domain + i + 1;
        else if (domain_delimiter[1] == NULL)
          domain_delimiter[1] = target_domain + i + 1;
        else if (domain_delimiter[2] == NULL)
          {
          domain_delimiter[2] = target_domain + i + 1;
          break;
          }
        }

    if (domain_delimiter[2] != NULL)
      snprintf(search_path, MAX_PATH, "%s" DIR_DELIMITER_STR "%.*s" DIR_DELIMITER_STR "%c" DIR_DELIMITER_STR "%.*s" DIR_DELIMITER_STR "%.*s" DIR_DELIMITER_STR "%.*s", start_directory, (int)(strlen_target_domain - (domain_delimiter[0] - target_domain)), domain_delimiter[0], domain_delimiter[1][0], (int)((domain_delimiter[0] - domain_delimiter[1]) - 1), domain_delimiter[1], (int)((domain_delimiter[1] - domain_delimiter[2]) - 1), domain_delimiter[2], strlen_target_domain, target_domain);
    else if (domain_delimiter[1] != NULL)
      snprintf(search_path, MAX_PATH, "%s" DIR_DELIMITER_STR "%.*s" DIR_DELIMITER_STR "%c" DIR_DELIMITER_STR "%.*s" DIR_DELIMITER_STR "%.*s", start_directory, (int)(strlen_target_domain - (domain_delimiter[0] - target_domain)), domain_delimiter[0], domain_delimiter[1][0], (int)((domain_delimiter[0] - domain_delimiter[1]) - 1), domain_delimiter[1], strlen_target_domain, target_domain);
    else if (domain_delimiter[0] != NULL)
      snprintf(search_path, MAX_PATH, "%s" DIR_DELIMITER_STR "%.*s" DIR_DELIMITER_STR "%c" DIR_DELIMITER_STR "%.*s" DIR_DELIMITER_STR "%.*s", start_directory, (int)(strlen_target_domain - (domain_delimiter[0] - target_domain)), domain_delimiter[0], target_domain[0], (int)((domain_delimiter[0] - target_domain) - 1), target_domain, strlen_target_domain, target_domain);
    else
      snprintf(search_path, MAX_PATH, "%s" DIR_DELIMITER_STR "%.*s" DIR_DELIMITER_STR "%c" DIR_DELIMITER_STR "%.*s", start_directory, strlen_target_domain, target_domain, target_domain[0], strlen_target_domain, target_domain);

    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DOMAIN_DIR, search_path);

    if (stat(search_path, &tmp_stat) == 0)
      return_value = search_path;
    else if ((base_domain = strchr(target_domain, '.')) != NULL)
      return_value = search_domain_directory(current_settings, start_directory, base_domain + 1, strlen_target_domain - ((base_domain + 1) - target_domain));
    }

  return(return_value);
  }

/*
 * start_line and end_line are 1-based.
 * if end_line is -1, return_content will be realloc()ed as lines are read.
 * if end_line is not -1, return_content must have at least ((end_line - start_line) + start_index + 1) entries preallocated.
 * individual entries will always be allocated.
 *
 * Return value:
 *   ERROR: -1
 *   SUCCESS: number of lines read, excluding skipped lines (1-based)
 */
int read_file(struct filter_settings *current_settings, char *target_filename, char ***return_content, int start_index, int start_line, int end_line, int all_lines)
  {
  int return_value;
  int i;
  int line_num;
  int usable_line_num;
  int strlen_line;
  int zero_start;
  FILE *tmp_file;
  char file_buf[MAX_FILE_BUF + 1];
  char **tmp_array;
  char *tmp_char;

  return_value = 0;
  line_num = 0;
  usable_line_num = start_index;

  if ((target_filename != NULL) &&
      (target_filename[0] != '\0') &&
      (return_content != NULL))
    {
    if ((tmp_file = fopen(target_filename, "r")) != NULL)
      {
      SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_OPEN_FILE, target_filename);

      zero_start = (start_line - 1) - start_index;

      if ((end_line == -1) &&
          (start_index == 0))
        *return_content = NULL;

      while (!feof(tmp_file) &&
             (line_num < MAX_FILE_LINES) &&
             ((end_line == -1) ||
              (line_num < end_line)))
        {
        if ((fscanf(tmp_file, "%" STRINGIFY(MAX_FILE_BUF) "[^\r\n]", file_buf) == 1) &&
            ((strlen_line = strlen(file_buf)) || 1) &&
            (all_lines ||
             ((file_buf[0] != COMMENT_DELIMITER) &&
              (strlen_line > 0))) &&
            (line_num >= zero_start))
          {
          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_READ_LINE, strlen_line, target_filename, line_num + 1, file_buf);

          if (end_line == -1)
            {
            if ((tmp_array = (char **)realloc(*return_content, sizeof(char *) * (usable_line_num + 2))) != NULL)
              {
              tmp_array[usable_line_num] = NULL;
              tmp_array[usable_line_num + 1] = NULL;
              *return_content = tmp_array;
              }
            else
              {
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char *) * (usable_line_num + 2));
              return_value = -1;
              break;
              }
            }

          if ((tmp_char = (char *)malloc(sizeof(char) * (strlen_line + 1))) != NULL)
            {
            (*return_content)[usable_line_num] = tmp_char;
            memcpy((*return_content)[usable_line_num], file_buf, sizeof(char) * strlen_line);
            (*return_content)[usable_line_num][strlen_line] = '\0';
            }
          else
            {
            SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char) * (strlen_line + 1));
            return_value = -1;
            break;
            }

          usable_line_num++;
          }

        fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      if (line_num == MAX_FILE_LINES)
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_FILE_TOO_LONG "%s", MAX_FILE_LINES, target_filename);

      fclose(tmp_file);

      if (return_value == 0)
        return_value = usable_line_num + 1;
      else
        {
        if ((*return_content) != NULL)
          {
          for (i = start_index; i < (line_num - zero_start); i++)
            if ((*return_content)[i] != NULL)
              free((*return_content)[i]);

          (*return_content)[start_index] = NULL;
          }

        if ((end_line == -1) &&
            (start_index == 0))
          {
          free(*return_content);
          *return_content = NULL;
          }
        }
      }
    else
      {
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_OPEN "%s: %s", target_filename, strerror(errno));
      return_value = -1;
      }
    }

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: -1
 *   SUCCESS: length of returned line
 */
int read_file_first_line(struct filter_settings *current_settings, char *target_filename, char **return_content)
  {
  int return_value;
  char *tmp_array[2];
  char **tmp_ptr;

  return_value = 0;

  tmp_array[0] = NULL;
  tmp_array[1] = NULL;

  /*
   * Without this, read_file() crashes on the statement (*return_content)[0] = tmp_char;
   * Why?
   */
  tmp_ptr = tmp_array;

  if ((return_content != NULL) &&
      (read_file(current_settings, target_filename, (char ***)&tmp_ptr, 0, 1, 1, 0) != -1))
    {
    *return_content = tmp_array[0];
    return_value = (tmp_array[0] != NULL) ? strlen(tmp_array[0]) : 0;
    }

  return(return_value);
  }

/*
 * Expects:
 *   return_address is a preallocated buffer
 *   max_return_address is the size of return_address, >= 0
 *
 * Return value:
 *   return_address, filled with the reassembled address OR missing_data if the address is empty
 */
char *reassemble_address(char *target_username, char *target_domain, char *missing_data, char *return_address, int max_return_address, int *strlen_return_address)
  {
  int tmp_strlen;

  tmp_strlen = 0;

  if ((return_address != NULL) &&
      (max_return_address >= 0))
    {
    if ((target_username != NULL) &&
        (target_username[0] != '\0'))
      if ((target_domain != NULL) &&
          (target_domain[0] != '\0'))
        tmp_strlen = SNPRINTF(return_address, max_return_address, "%s@%s", target_username, target_domain);
      else
        tmp_strlen = SNPRINTF(return_address, max_return_address, "%s", target_username);
    else if ((target_domain != NULL) &&
             (target_domain[0] != '\0'))
      tmp_strlen = SNPRINTF(return_address, max_return_address, "@%s", target_domain);
    else if (missing_data != NULL)
      tmp_strlen = SNPRINTF(return_address, max_return_address, "%s", missing_data);
    else
      return_address[0] = '\0';
    }

  if (strlen_return_address != NULL)
    *strlen_return_address = tmp_strlen;

  return(return_address);
  }

/*
 * Reduces any sequences of one or more whitespace characters to a single space
 * and also converts the text to lowercase.
 *
 * Return value:
 *   -1: error
 *   number of characters copied to target_buf
 */
int collapse_whitespace(struct filter_settings *current_settings, char *target_buf, int strlen_target_buf, char *input_buf, int strlen_input_buf)
  {
  int return_value;
  int i;
  int tmp_strlen;

  return_value = -1;

  if ((target_buf != NULL) &&
      (strlen_target_buf > 0))
    {
    tmp_strlen = 0;

    for (i = 0; (i < strlen_input_buf) && (i < strlen_target_buf); i++)
      if (isspace((int)input_buf[i]))
        {
        if ((tmp_strlen == 0) ||
            (target_buf[tmp_strlen - 1] != ' '))
          {
          target_buf[tmp_strlen] = ' ';
          tmp_strlen++;
          }
        }
      else
        {
        target_buf[tmp_strlen] = tolower((int)input_buf[i]);
        tmp_strlen++;
        }

    for (i = (tmp_strlen - 1); (i >= 0) && (target_buf[i] == ' '); i--)
      tmp_strlen--;

    target_buf[tmp_strlen] = '\0';
    return_value = tmp_strlen;

    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_COLLAPSE_WHITESPACE, strlen_input_buf, strlen_input_buf, input_buf, tmp_strlen, tmp_strlen, target_buf);
    }

  return(return_value);
  }

/*
 * Return value:
 *   0: no match
 *   1: match found
 */
int examine_header(struct filter_settings *current_settings, char *target_header, int strlen_target_header, char *target_entry, int strlen_target_entry)
  {
  int return_value;
  char tmp_header[MAX_NETWORK_BUF + 1];
  int strlen_tmp_header;
  char tmp_entry[MAX_NETWORK_BUF + 1];
  int strlen_tmp_entry;

  return_value = 0;

  if ((target_header != NULL) &&
      (strlen_target_header > 0) &&
      (target_entry != NULL) &&
      (strlen_target_entry > 0) &&
      (strchr(target_entry, HEADER_DELIMITER) != NULL) &&
      (strchr(target_header, HEADER_DELIMITER) != NULL) &&
      ((strlen_tmp_header = collapse_whitespace(current_settings, tmp_header, MAX_NETWORK_BUF, target_header, strlen_target_header)) > 0) &&
      ((strlen_tmp_entry = collapse_whitespace(current_settings, tmp_entry, MAX_NETWORK_BUF, target_entry, strlen_target_entry)) > 0) &&
      (fnmatch(tmp_entry, tmp_header, 0) == 0))
    return_value = 1;

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: -1
 *   NOT FOUND: 0
 *   FOUND: matching line number
 */
int search_header_file(struct filter_settings *current_settings, char *search_filename, char *target_header, int strlen_target_header)
  {
  int return_value;
  FILE *tmp_file;
  char tmp_buf[MAX_FILE_BUF + 1];
  int line_num;
  int strlen_buf;
  char tmp_header[MAX_NETWORK_BUF + 1];
  int strlen_tmp_header;
  char tmp_entry[MAX_NETWORK_BUF + 1];
  int strlen_tmp_entry;

  return_value = 0;

  if ((target_header != NULL) &&
      (strlen_target_header > 0) &&
      (strchr(target_header, HEADER_DELIMITER) != NULL) &&
      ((strlen_tmp_header = collapse_whitespace(current_settings, tmp_header, MAX_NETWORK_BUF, target_header, strlen_target_header)) > 0))
    {
    if ((tmp_file = fopen(search_filename, "r")) != NULL)
      {
      line_num = 0;

      while (!feof(tmp_file) &&
             (line_num < MAX_FILE_LINES))
        {
        if ((fscanf(tmp_file, "%" STRINGIFY(MAX_FILE_BUF) "[^\r\n]", tmp_buf) == 1) &&
            (tmp_buf[0] != COMMENT_DELIMITER) &&
            ((strlen_buf = strlen(tmp_buf)) > 0) &&
            (strchr(tmp_buf, HEADER_DELIMITER) != NULL) &&
            ((strlen_tmp_entry = collapse_whitespace(current_settings, tmp_entry, MAX_NETWORK_BUF, tmp_buf, strlen_buf)) > 0) &&
            (fnmatch(tmp_entry, tmp_header, 0) == 0))
          {
          return_value = line_num + 1;
          break;
          }

        fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      if (line_num == MAX_FILE_LINES)
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_FILE_TOO_LONG "%s", MAX_FILE_LINES, search_filename);

      fclose(tmp_file);
      }
    else
      {
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_OPEN_SEARCH "%s: %s", search_filename, strerror(errno));
      return_value = -1;
      }
    }

  return(return_value);
  }

/*
 * EXPECTS:
 *   type_flag should be a value within the S_IFMT mask in stat.h -- S_IFDIR, S_IFREG, etc
 *   permission_flags should be an OR of FILE_PERMISSION_READ, FILE_PERMISSION_WRITE or FILE_PERMISSION_EXECUTE, not bitshifted for user/group/other.
 *   if target_uid is -1, geteuid() will be used
 *   if target_gid is -1, getegid() and secondary groups will be used
 *
 * RETURNS:
 *  -1: error
 *  0: file does not exist, is the wrong type or does not have permissions
 *  1: file exists, is the correct type and has the permissions
 */
int check_path_perms(struct filter_settings *current_settings, char *target_path, int type_flag, int permission_flags, struct stat *target_stat, int target_uid, int target_gid)
  {
  int return_value;
  int i;
  struct stat *tmp_stat;
  struct stat internal_stat;
  int found_match;
  int num_groups;
  gid_t *tmp_gid;

  return_value = 0;
  tmp_gid = NULL;

  if (target_path != NULL)
    {
    tmp_stat = (target_stat != NULL) ? target_stat : &internal_stat;
    if (!stat(target_path, tmp_stat))
      {
      SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_FILE_STAT, tmp_stat->st_mode, type_flag, tmp_stat->st_uid, tmp_stat->st_gid, target_path);

      if (((type_flag == 0) ||
           ((tmp_stat->st_mode & S_IFMT) == type_flag)) &&
          (((permission_flags & FILE_PERMISSION_SETUID) == 0) ||
           (tmp_stat->st_mode & S_ISUID)) &&
          (((permission_flags & FILE_PERMISSION_SETGID) == 0) ||
           (tmp_stat->st_mode & S_ISGID)) &&
          (((permission_flags & FILE_PERMISSION_STICKY) == 0) ||
           (tmp_stat->st_mode & S_ISVTX)))
        {
        if ((permission_flags & FILE_PERMISSION_READ) ||
            (permission_flags & FILE_PERMISSION_WRITE) ||
            (permission_flags & FILE_PERMISSION_EXECUTE))
          {
          if (((target_uid != -1) &&
               (tmp_stat->st_uid == target_uid)) ||
              ((target_uid == -1) &&
               (tmp_stat->st_uid == geteuid())))
            {
            if ((((permission_flags & FILE_PERMISSION_READ) == 0) ||
                 (tmp_stat->st_mode & S_IRUSR)) &&
                (((permission_flags & FILE_PERMISSION_WRITE) == 0) ||
                 (tmp_stat->st_mode & S_IWUSR)) &&
                (((permission_flags & FILE_PERMISSION_EXECUTE) == 0) ||
                 (tmp_stat->st_mode & S_IXUSR)))
              return_value = 1;
            }
          else
            {
            found_match = 0;

            if (target_gid != -1)
              {
              if (tmp_stat->st_gid == target_gid)
                found_match = 1;
              }
            else if (tmp_stat->st_gid == getegid())
              found_match = 1;
            else if ((num_groups = getgroups(0, NULL)) > 0)
              {
              if ((tmp_gid = (gid_t *)malloc(sizeof(gid_t) * num_groups)) != NULL)
                {
                if (getgroups(num_groups, tmp_gid) > 0)
                  for (i = 0; i < num_groups; i++)
                    if (tmp_stat->st_gid == tmp_gid[i])
                      {
                      /* Secondary group owns the directory. */
                      found_match = 1;
                      break;
                      }

                free(tmp_gid);
                tmp_gid = NULL;
                }
              else
                {
                SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (long)(sizeof(gid_t) * num_groups));
                return_value = -1;
                }
              }

            if (found_match)
              {
              if ((((permission_flags & FILE_PERMISSION_READ) == 0) ||
                   (tmp_stat->st_mode & S_IRGRP)) &&
                  (((permission_flags & FILE_PERMISSION_WRITE) == 0) ||
                   (tmp_stat->st_mode & S_IWGRP)) &&
                  (((permission_flags & FILE_PERMISSION_EXECUTE) == 0) ||
                   (tmp_stat->st_mode & S_IXGRP)))
                return_value = 1;
              }
            else
              if ((((permission_flags & FILE_PERMISSION_READ) == 0) ||
                   (tmp_stat->st_mode & S_IROTH)) &&
                  (((permission_flags & FILE_PERMISSION_WRITE) == 0) ||
                   (tmp_stat->st_mode & S_IWOTH)) &&
                  (((permission_flags & FILE_PERMISSION_EXECUTE) == 0) ||
                   (tmp_stat->st_mode & S_IXOTH)))
                return_value = 1;
            }
          }
        else
          return_value = 1;
        }
      }
    else if ((errno == EACCES) ||
             (errno == ENOENT) ||
             (errno == ENOTDIR))
      {
      SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_FILE_STAT_FAIL, target_path, strerror(errno));
      return_value = 0;
      }
    else
      {
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_STAT_ERRNO, target_path, strerror(errno));
      return_value = -1;
      }
    }

  return(return_value);
  }
