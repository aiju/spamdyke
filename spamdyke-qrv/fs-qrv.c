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
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include "spamdyke-qrv.h"
#include "fs-qrv.h"
#include "log-qrv.h"

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
int search_file(struct qrv_settings *current_settings, char *search_filename, char *target_string, int strlen_target_string, char start_wildcard, char *start_wildcard_matches, char end_wildcard, char *end_wildcard_matches)
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
  struct stat tmp_stat;

  return_value = 0;

  if ((target_string != NULL) &&
      (strlen_target_string > 0))
    {
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_SEARCH_FILE, search_filename, strlen_target_string, target_string);

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
        QRV_LOG_VERBOSE(current_settings, LOG_VERBOSE_FILE_TOO_LONG "%s", MAX_FILE_LINES, search_filename);

      fclose(tmp_file);
      }
    else if ((stat(search_filename, &tmp_stat) == -1) &&
             (errno == ENOENT))
      return_value = 0;
    else
      {
      QRV_LOG_ERROR(current_settings, LOG_ERROR_OPEN_SEARCH "%s: %s", search_filename, strerror(errno));
      return_value = -1;
      }
    }

  return(return_value);
  }

/*
 * RETURNS:
 *   -1 = error
 *   0 = no match
 *   >0 = line number where match was found
 */
int search_virtualdomains_file(struct qrv_settings *current_settings, char *search_filename, char *target_domain, int strlen_target_domain, char *return_entry, int *size_return_entry)
  {
  int return_value;
  FILE *tmp_file;
  char tmp_buf[MAX_FILE_BUF + 1];
  int line_num;
  int i;
  int strlen_buf;
  char lower_target_domain[MAX_BUF + 1];
  int strlen_lower_target_domain;

  return_value = 0;

  if ((search_filename != NULL) &&
      (target_domain != NULL) &&
      (strlen_target_domain > 0))
    {
    if ((tmp_file = fopen(search_filename, "r")) != NULL)
      {
      line_num = 0;

      strlen_lower_target_domain = MINVAL(MAX_BUF, strlen_target_domain);
      for (i = 0; i < strlen_lower_target_domain; i++)
        lower_target_domain[i] = tolower((int)target_domain[i]);

      while (!feof(tmp_file) &&
             (line_num < MAX_FILE_LINES))
        {
        if ((fscanf(tmp_file, "%" STRINGIFY(MAX_FILE_BUF) "[^\r\n]", tmp_buf) == 1) &&
            (tmp_buf[0] != COMMENT_DELIMITER) &&
            ((strlen_buf = strlen(tmp_buf)) > 0) &&
            (strlen_buf > strlen_lower_target_domain) &&
            !strncmp(tmp_buf, lower_target_domain, strlen_lower_target_domain) &&
            (tmp_buf[strlen_lower_target_domain] == VIRTUALDOMAINS_DELIMITER))
          {
          return_value = line_num + 1;

          if ((return_entry != NULL) &&
              (size_return_entry != NULL) &&
              ((*size_return_entry) > 0))
            {
            *size_return_entry = MINVAL(strlen_buf - (strlen_lower_target_domain + 1), *size_return_entry);
            memcpy(return_entry, tmp_buf + strlen_lower_target_domain + 1, *size_return_entry);
            return_entry[*size_return_entry] = '\0';
            }

          break;
          }

        fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      if (line_num == MAX_FILE_LINES)
        QRV_LOG_VERBOSE(current_settings, LOG_VERBOSE_FILE_TOO_LONG "%s", MAX_FILE_LINES, search_filename);

      fclose(tmp_file);
      }
    else
      {
      QRV_LOG_ERROR(current_settings, LOG_ERROR_OPEN_SEARCH "%s: %s", search_filename, strerror(errno));
      return_value = -1;
      }
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
int read_file(struct qrv_settings *current_settings, char *target_filename, char ***return_content, int start_index, int start_line, int end_line, int all_lines)
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
  usable_line_num = 0;

  if ((target_filename != NULL) &&
      (target_filename[0] != '\0') &&
      (return_content != NULL))
    {
    if ((tmp_file = fopen(target_filename, "r")) != NULL)
      {
      QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_OPEN_FILE, target_filename);

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
          QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_READ_LINE, strlen_line, target_filename, line_num + 1, file_buf);

          if (end_line == -1)
            {
            if ((tmp_array = (char **)realloc(*return_content, sizeof(char *) * ((line_num - zero_start) + 2))) != NULL)
              {
              tmp_array[line_num - zero_start] = NULL;
              tmp_array[(line_num - zero_start) + 1] = NULL;
              *return_content = tmp_array;
              }
            else
              {
              QRV_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char *) * ((line_num - zero_start) + 2));
              return_value = -1;
              break;
              }
            }

          if ((tmp_char = (char *)malloc(sizeof(char) * (strlen_line + 1))) != NULL)
            {
            (*return_content)[line_num - zero_start] = tmp_char;
            memcpy((*return_content)[line_num - zero_start], file_buf, sizeof(char) * strlen_line);
            (*return_content)[line_num - zero_start][strlen_line] = '\0';
            }
          else
            {
            QRV_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char) * (strlen_line + 1));
            return_value = -1;
            break;
            }

          usable_line_num++;
          }

        fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      if (line_num == MAX_FILE_LINES)
        QRV_LOG_VERBOSE(current_settings, LOG_VERBOSE_FILE_TOO_LONG "%s", MAX_FILE_LINES, target_filename);

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
      QRV_LOG_ERROR(current_settings, LOG_ERROR_OPEN "%s: %s", target_filename, strerror(errno));
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
int read_file_first_line(struct qrv_settings *current_settings, char *target_filename, char **return_content)
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
 *   strlen_username is the length of the username if not NULL-terminated, or -1 if NULL-terminated
 *   return_address is a preallocated buffer
 *   max_return_address is the size of return_address, >= 0
 *
 * Return value:
 *   return_address, filled with the reassembled address OR missing_data if the address is empty
 */
char *reassemble_address(char *target_username, int strlen_username, char *target_domain, char *missing_data, char *return_address, int max_return_address, int *strlen_return_address)
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
        {
        if (strlen_username == -1)
          tmp_strlen = SNPRINTF(return_address, max_return_address, "%s@%s", target_username, target_domain);
        else
          tmp_strlen = SNPRINTF(return_address, max_return_address, "%.*s@%s", strlen_username, target_username, target_domain);
        }
      else
        if (strlen_username == -1)
          tmp_strlen = SNPRINTF(return_address, max_return_address, "%s", target_username);
        else
          tmp_strlen = SNPRINTF(return_address, max_return_address, "%.*s", strlen_username, target_username);
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
int check_path_perms(struct qrv_settings *current_settings, char *target_path, int type_flag, int permission_flags, struct stat *target_stat, int target_uid, int target_gid)
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
      QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_FILE_STAT, tmp_stat->st_mode, type_flag, tmp_stat->st_uid, tmp_stat->st_gid, target_path);

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
                QRV_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (long)(sizeof(gid_t) * num_groups));
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
    else if ((errno == ENOENT) ||
             (errno == ENOTDIR))
      {
      QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_FILE_STAT_FAIL, target_path, strerror(errno));
      return_value = 0;
      }
    else
      {
      QRV_LOG_ERROR(current_settings, LOG_ERROR_STAT_ERRNO, target_path, strerror(errno));
      return_value = -1;
      }
    }

  return(return_value);
  }

/*
 * Return value:
 *   NOT FOUND: 0
 *   FOUND: 1
 */
int find_path(struct qrv_settings *current_settings, char *filename, char *return_filename, int size_return_filename)
  {
  int return_value;
  int strlen_filename;
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
      tmp_start = current_settings->path;
      tmp_end = NULL;
      while (tmp_start != NULL)
        {
        if ((tmp_end = strchr(tmp_start, ENVIRONMENT_SEPARATOR)) != NULL)
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
 * EXPECTS:
 *   type_flag should be a value within the S_IFMT mask in stat.h -- S_IFDIR, S_IFREG, etc
 *   permission_flags should be an OR of FILE_PERMISSION_READ, FILE_PERMISSION_WRITE or FILE_PERMISSION_EXECUTE, not bitshifted for user/group/other.
 *
 * RETURNS:
 *  -1: error
 *  0: file does not exist, is the wrong type or does not have permissions
 *  1: file exists, is the correct type and has the permissions
 */
int find_path_perms(struct qrv_settings *current_settings, char *target_path, int type_flag, int permission_flags, int target_uid, int target_gid)
  {
  int return_value;
  char tmp_cwd[MAX_PATH + 1];
  char tmp_path[MAX_PATH + 1];

  return_value = 0;

  if (target_path != NULL)
    {
    if (target_path[0] == DIR_DELIMITER)
      return_value = check_path_perms(current_settings, target_path, type_flag, permission_flags, NULL, target_uid, target_gid);
    else
      {
      if (strchr(target_path, DIR_DELIMITER) != NULL)
        {
        if (getcwd(tmp_cwd, MAX_PATH) != NULL)
          {
          snprintf(tmp_path, MAX_PATH, "%s%c%s", tmp_cwd, DIR_DELIMITER, target_path);
          return_value = check_path_perms(current_settings, tmp_path, type_flag, permission_flags, NULL, target_uid, target_gid);
          }
        else
          {
          QRV_LOG_ERROR(current_settings, LOG_ERROR_GETCWD, strerror(errno));
          return_value = -1;
          }
        }
      else if (find_path(current_settings, target_path, tmp_path, MAX_PATH))
        return_value = check_path_perms(current_settings, tmp_path, type_flag, permission_flags, NULL, target_uid, target_gid);
      }
    }

  return(return_value);
  }
