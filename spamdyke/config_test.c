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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#include "config.h"

#ifdef TIME_WITH_SYS_TIME

#include <sys/time.h>
#include <time.h>

#else /* TIME_WITH_SYS_TIME */
#ifdef HAVE_SYS_TIME_H

#include <sys/time.h>

#else /* HAVE_SYS_TIME_H */

#include <time.h>

#endif /* HAVE_SYS_TIME_H */
#endif /* TIME_WITH_SYS_TIME */

#include "spamdyke.h"
#include "log.h"
#include "usage.h"
#include "tls.h"
#include "environment.h"
#include "exec.h"
#include "md5.h"
#include "search_fs.h"
#include "configuration.h"
#include "cdb.h"
#include "config_test.h"

#ifndef WITHOUT_CONFIG_TEST

mode_t config_test_file_type(char *target_dir, struct dirent *target_entry)
  {
  mode_t return_value;
  struct stat tmp_stat;
  char tmp_filepath[MAX_BUF + 1];

#ifndef HAVE_STRUCT_DIRENT_D_TYPE

  if ((snprintf(tmp_filepath, MAX_BUF, "%s" DIR_DELIMITER_STR "%s", target_dir, target_entry->d_name) > 0) &&
      (stat(tmp_filepath, &tmp_stat) == 0))
    return_value = tmp_stat.st_mode & S_IFMT;
  else
    return_value = 0;

#else /* HAVE_STRUCT_DIRENT_D_TYPE */

  switch (target_entry->d_type)
    {
    case DT_FIFO:
      return_value = S_IFIFO;
      break;
    case DT_CHR:
      return_value = S_IFCHR;
      break;
    case DT_DIR:
      return_value = S_IFDIR;
      break;
    case DT_BLK:
      return_value = S_IFBLK;
      break;
    case DT_REG:
      return_value = S_IFREG;
      break;
    case DT_LNK:
      return_value = S_IFLNK;
      break;
    case DT_SOCK:
      return_value = S_IFSOCK;
      break;

#ifdef HAVE_WHITEOUT

    case DT_WHT:
      return_value = S_IFWHT;
      break;

#endif /* HAVE_WHITEOUT */

    default:
      if ((snprintf(tmp_filepath, MAX_BUF, "%s" DIR_DELIMITER_STR "%s", target_dir, target_entry->d_name) > 0) &&
          (stat(tmp_filepath, &tmp_stat) == 0))
        return_value = tmp_stat.st_mode & S_IFMT;
      else
        return_value = 0;

      break;
    }

#endif /* HAVE_STRUCT_DIRENT_D_TYPE */

  return(return_value);
  }

/*
 * Return value:
 *   static string from spamdyke.h
 */
char *config_test_stat_type(mode_t type)
  {
  char *return_value;

  switch (type & S_IFMT)
    {
    case S_IFIFO:
      return_value = CONFIG_TEST_TYPE_IFIFO;
      break;
    case S_IFCHR:
      return_value = CONFIG_TEST_TYPE_IFCHR;
      break;
    case S_IFDIR:
      return_value = CONFIG_TEST_TYPE_IFDIR;
      break;
    case S_IFBLK:
      return_value = CONFIG_TEST_TYPE_IFBLK;
      break;
    case S_IFREG:
      return_value = CONFIG_TEST_TYPE_IFREG;
      break;
    case S_IFLNK:
      return_value = CONFIG_TEST_TYPE_IFLNK;
      break;
    case S_IFSOCK:
      return_value = CONFIG_TEST_TYPE_IFSOCK;
      break;

#ifdef HAVE_WHITEOUT

    case S_IFWHT:
      return_value = CONFIG_TEST_TYPE_IFWHT;
      break;

#endif /* HAVE_WHITEOUT */

    default:
      return_value = CONFIG_TEST_TYPE_UNKNOWN;
      break;
    }

  return(return_value);
  }

/*
 * Return value:
 *   static string from spamdyke.h
 */
char *config_test_file_type_string(char *target_dir, struct dirent *target_entry)
  {
  return(config_test_stat_type(config_test_file_type(target_dir, target_entry)));
  }

char *config_test_find_integer_string(struct integer_string *target_list, int target_integer)
  {
  char *return_value;
  int i;

  return_value = NULL;

  if ((target_list != NULL) &&
      (target_list->integers != NULL) &&
      (target_list->strings != NULL))
    for (i = 0; target_list->strings[i] != NULL; i++)
      if (target_list->integers[i] == target_integer)
        {
        return_value = target_list->strings[i];
        break;
        }

  return(return_value);
  }

/*
 * Expects:
 *   target_file may be NULL
 *   start_message may be NULL
 *   success_message may be NULL
 *   failure_message may be NULL
 *
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_file_read(struct filter_settings *current_settings, char *target_file, char *option_name, char *start_message, char *success_message, char *failure_message, char *failure_overlength_message, int line_recommendation, char *failure_overrecommendation_message)
  {
  int return_value;
  FILE *tmp_file;
  char tmp_buf[MAX_FILE_BUF + 1];
  int line_num;

  return_value = 1;

  if (target_file != NULL)
    {
    SPAMDYKE_LOG_VERBOSE(current_settings, start_message, option_name, target_file);

    if ((tmp_file = fopen(target_file, "r")) != NULL)
      {
      line_num = 0;

      while (!feof(tmp_file) &&
             (line_num < MAX_FILE_LINES))
        {
        fscanf(tmp_file, "%" STRINGIFY(MAX_FILE_BUF) "[^\r\n]", tmp_buf);
        fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      if ((failure_overlength_message != NULL) &&
          (line_num >= MAX_FILE_LINES))
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_overlength_message, option_name, MAX_FILE_LINES, target_file);
        return_value = 0;
        }
      else if ((line_recommendation > 0) &&
               (failure_overrecommendation_message != NULL) &&
               (line_num > line_recommendation))
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_overrecommendation_message, option_name, target_file);
      else
        SPAMDYKE_LOG_INFO(current_settings, success_message, option_name, target_file);

      fclose(tmp_file);
      }
    else
      {
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_message, option_name, target_file, strerror(errno));
      return_value = 0;
      }
    }

  return(return_value);
  }

/*
 * Expects:
 *   target_file may be NULL
 *   start_message may be NULL
 *   success_message may be NULL
 *   failure_message may be NULL
 *
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_file_write(struct filter_settings *current_settings, char *target_file, char *option_name, char *start_message, char *success_message, char *failure_message)
  {
  int return_value;
  FILE *tmp_file;

  return_value = 1;

  if (target_file != NULL)
    {
    SPAMDYKE_LOG_VERBOSE(current_settings, start_message, option_name, target_file);

    if ((tmp_file = fopen(target_file, "a")) != NULL)
      {
      SPAMDYKE_LOG_INFO(current_settings, success_message, option_name, target_file);
      fclose(tmp_file);
      }
    else
      {
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_message, option_name, target_file, strerror(errno));
      return_value = 0;
      }
    }

  return(return_value);
  }

/*
 * Expects:
 *   target_file may be NULL
 *   start_message may be NULL
 *   success_message may be NULL
 *   failure_message may be NULL
 *
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_file_read_write(struct filter_settings *current_settings, char *target_file, char *option_name, char *start_message, char *success_message, char *failure_message, char *failure_overlength_message, int line_recommendation, char *failure_overrecommendation_message)
  {
  int return_value;
  FILE *tmp_file;
  char tmp_buf[MAX_FILE_BUF + 1];
  int line_num;

  return_value = 1;

  if (target_file != NULL)
    {
    SPAMDYKE_LOG_VERBOSE(current_settings, start_message, option_name, target_file);

    if ((tmp_file = fopen(target_file, "a+")) != NULL)
      {
      line_num = 0;

      while (!feof(tmp_file) &&
             (line_num < MAX_FILE_LINES))
        {
        fscanf(tmp_file, "%" STRINGIFY(MAX_FILE_BUF) "[^\r\n]", tmp_buf);
        fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      if ((failure_overlength_message != NULL) &&
          (line_num >= MAX_FILE_LINES))
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_overlength_message, option_name, MAX_FILE_LINES, target_file);
        return_value = 0;
        }
      else if ((line_recommendation > 0) &&
               (failure_overrecommendation_message != NULL) &&
               (line_num > line_recommendation))
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_overrecommendation_message, option_name, target_file);
      else
        SPAMDYKE_LOG_INFO(current_settings, success_message, option_name, target_file);

      fclose(tmp_file);
      }
    else
      {
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_message, option_name, target_file, strerror(errno));
      return_value = 0;
      }
    }

  return(return_value);
  }

/*
 * Expects:
 *   target_file may be NULL
 *   start_message may be NULL
 *   success_message may be NULL
 *   failure_message may be NULL
 *   option_name may be NULL if start_message, success_message and failure_message are all NULL
 *
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_file_execute(struct filter_settings *current_settings, char *target_file, char *option_name, char *start_message, char *success_message, char *failure_message, struct stat *target_stat)
  {
  int return_value;
  int check_return;

  return_value = 1;

  if (target_file != NULL)
    {
    SPAMDYKE_LOG_VERBOSE(current_settings, start_message, option_name, target_file);

    if ((check_return = check_path_perms(current_settings, target_file, S_IFREG, FILE_PERMISSION_EXECUTE, target_stat, -1, -1)) == 1)
      SPAMDYKE_LOG_INFO(current_settings, success_message, option_name, target_file);
    else if (check_return == 0)
      {
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_message, option_name, target_file, CONFIG_TEST_MSG_NO_EXEC);
      return_value = 0;
      }
    else
      {
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_message, option_name, target_file, strerror(errno));
      return_value = 0;
      }
    }

  return(return_value);
  }

/*
 * Expects:
 *   target_dir may be NULL
 *   start_message may be NULL
 *   success_message may be NULL
 *   failure_message may be NULL
 *
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_dir_read(struct filter_settings *current_settings, char *target_dir, char *option_name, char *start_message, char *success_message, char *failure_message)
  {
  int return_value;
  int test_return;
  DIR *tmp_dir;
  struct dirent *tmp_ent;
  struct stat tmp_stat;
  char tmp_name[MAX_BUF + 1];

  return_value = 1;

  if (target_dir != NULL)
    {
    SPAMDYKE_LOG_VERBOSE(current_settings, start_message, option_name, target_dir);

    if ((tmp_dir = opendir(target_dir)) != NULL)
      {
      while ((tmp_ent = readdir(tmp_dir)) != NULL)
        if ((strcmp(tmp_ent->d_name, DIR_CURRENT) != 0) &&
            (strcmp(tmp_ent->d_name, DIR_PARENT) != 0))
          {
          snprintf(tmp_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s", target_dir, tmp_ent->d_name);
          switch (config_test_file_type(target_dir, tmp_ent))
            {
            case S_IFDIR:
              test_return = config_test_dir_read(current_settings, tmp_name, option_name, NULL, NULL, failure_message);
              if (return_value)
                return_value = test_return;

              break;
            case S_IFREG:
              if (stat(tmp_name, &tmp_stat) != 0)
                {
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_message, option_name, tmp_name, strerror(errno));
                return_value = 0;
                }

              break;
            }
          }

      closedir(tmp_dir);

      if (return_value &&
          (success_message != NULL))
        SPAMDYKE_LOG_INFO(current_settings, success_message, option_name, target_dir);
      }
    else
      {
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_message, option_name, target_dir, strerror(errno));
      return_value = 0;
      }
    }

  return(return_value);
  }

/*
 * Expects:
 *   target_dir may be NULL
 *   start_message may be NULL
 *   success_message may be NULL
 *   failure_message_create may be NULL
 *   failure_message_delete may be NULL
 *
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_dir_write(struct filter_settings *current_settings, char *target_dir, char *option_name, char *start_message, char *success_message, char *failure_message_create, char *failure_message_delete)
  {
  int return_value;
  char tmp_name[MAX_BUF + 1];
  FILE *tmp_file;

  return_value = 1;

  if (target_dir != NULL)
    {
    SPAMDYKE_LOG_VERBOSE(current_settings, start_message, option_name, target_dir);

    snprintf(tmp_name, MAX_BUF, "%s" DIR_DELIMITER_STR "spamdyke-test_%u_" FORMAT_PID_T, target_dir, (unsigned int)time(NULL), getpid());
    if ((tmp_file = fopen(tmp_name, "w")) != NULL)
      {
      fclose(tmp_file);

      if (unlink(tmp_name) == 0)
        SPAMDYKE_LOG_INFO(current_settings, success_message, option_name, tmp_name);
      else
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_message_delete, option_name, tmp_name, strerror(errno));
        return_value = 0;
        }
      }
    else
      {
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, failure_message_create, option_name, tmp_name, strerror(errno));
      return_value = 0;
      }
    }

  return(return_value);
  }

/*
 * Return value:
 *   1
 */
int config_test_noop(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(1);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_graylist(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;
  int i;
  int j;
  int k;
  int match_found;
  int test_return;
  DIR *top_dir;
  DIR *domain_dir;
  DIR *user_dir;
  DIR *sender_dir;
  struct dirent *top_ent;
  struct dirent *domain_ent;
  struct dirent *user_ent;
  struct dirent *sender_ent;
  char top_name[MAX_BUF + 1];
  char domain_name[MAX_BUF + 1];
  char user_name[MAX_BUF + 1];
  char sender_name[MAX_BUF + 1];
  char ***accept_domain_list;

  return_value = 1;

  /* FIXME: extend this to also check CDB files */
  accept_domain_list = NULL;
  if (((current_settings->current_options->qmail_rcpthosts_file != NULL) &&
       (current_settings->current_options->qmail_rcpthosts_file[0] != NULL)))
    {
    i = 0;
    if (current_settings->current_options->qmail_rcpthosts_file != NULL)
      for (i = 0; current_settings->current_options->qmail_rcpthosts_file[i] != NULL; i++);

    if ((accept_domain_list = (char ***)malloc(sizeof(char **) * (i + 1))) != NULL)
      {
      for (j = 0; j <= i; j++)
        accept_domain_list[j] = NULL;

      if (current_settings->current_options->qmail_rcpthosts_file != NULL)
        for (i = 0; current_settings->current_options->qmail_rcpthosts_file[i] != NULL; i++)
          if (read_file(current_settings, current_settings->current_options->qmail_rcpthosts_file[i], accept_domain_list + i, 0, 1, -1, 0) == -1)
            {
            return_value = 0;
            break;
            }
      }
    else
      {
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char **) * (i + 1));
      return_value = 0;
      }
    }

  if ((return_value == 1) &&
      ((current_settings->current_options->graylist_level & GRAYLIST_LEVEL_NONE) == GRAYLIST_LEVEL_NONE) &&
      ((current_settings->current_options->graylist_dir != NULL) ||
       (current_settings->current_options->graylist_exception_ip != NULL) ||
       (current_settings->current_options->graylist_exception_ip_file != NULL) ||
       (current_settings->current_options->graylist_exception_rdns_dir != NULL) ||
       (current_settings->current_options->graylist_exception_rdns != NULL) ||
       (current_settings->current_options->graylist_exception_rdns_file != NULL) ||
       (current_settings->current_options->graylist_max_secs != 0) ||
       (current_settings->current_options->graylist_min_secs != 0)))
    {
    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_GRAYLIST_NONE_OPTIONS, target_option->getopt_option.name);
    return_value = 0;
    }

  if ((return_value == 1) &&
      (current_settings->current_options->graylist_dir != NULL))
    for (i = 0; current_settings->current_options->graylist_dir[i] != NULL; i++)
      {
      SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_START_GRAYLIST, target_option->getopt_option.name, current_settings->current_options->graylist_dir[i]);

      if ((top_dir = opendir(current_settings->current_options->graylist_dir[i])) != NULL)
        {
        while ((top_ent = readdir(top_dir)) != NULL)
          if ((strcmp(top_ent->d_name, DIR_CURRENT) != 0) &&
              (strcmp(top_ent->d_name, DIR_PARENT) != 0))
            {
            snprintf(top_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s", current_settings->current_options->graylist_dir[i], top_ent->d_name);
            if (S_ISDIR(config_test_file_type(current_settings->current_options->graylist_dir[i], top_ent)))
              {
              SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TEST_GRAYLIST_DOMAIN_DIR, top_name);

              if (accept_domain_list != NULL)
                {
                match_found = 0;

                for (k = 0; accept_domain_list[k] != NULL; k++)
                  for (j = 0; accept_domain_list[k][j] != NULL; j++)
                    if ((accept_domain_list[k][j][0] != '\0') &&
                        (strcmp(accept_domain_list[k][j], top_ent->d_name) == 0))
                      {
                      accept_domain_list[k][j][0] = '\0';
                      match_found = 1;
                      }

                if (!match_found)
                  SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_GRAYLIST_TOP_ORPHAN, target_option->getopt_option.name, top_name);
                }

              test_return = config_test_dir_write(current_settings, top_name, (char *)target_option->getopt_option.name, NULL, NULL, CONFIG_TEST_ERROR_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE_DELETE);
              if (return_value)
                return_value = test_return;

              if ((domain_dir = opendir(top_name)) != NULL)
                {
                while ((domain_ent = readdir(domain_dir)) != NULL)
                  if ((strcmp(domain_ent->d_name, DIR_CURRENT) != 0) &&
                      (strcmp(domain_ent->d_name, DIR_PARENT) != 0))
                    {
                    snprintf(domain_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s", current_settings->current_options->graylist_dir[i], top_ent->d_name, domain_ent->d_name);
                    if (S_ISDIR(config_test_file_type(top_name, domain_ent)))
                      {
                      SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TEST_GRAYLIST_USER_DIR, top_name);

                      test_return = config_test_dir_write(current_settings, domain_name, (char *)target_option->getopt_option.name, NULL, NULL, CONFIG_TEST_ERROR_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE_DELETE);
                      if (return_value)
                        return_value = test_return;

                      if ((user_dir = opendir(domain_name)) != NULL)
                        {
                        while ((user_ent = readdir(user_dir)) != NULL)
                          if ((strcmp(user_ent->d_name, DIR_CURRENT) != 0) &&
                              (strcmp(user_ent->d_name, DIR_PARENT) != 0))
                            {
                            snprintf(user_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s", current_settings->current_options->graylist_dir[i], top_ent->d_name, domain_ent->d_name, user_ent->d_name);
                            if (S_ISDIR(config_test_file_type(user_name, domain_ent)))
                              {
                              SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TEST_GRAYLIST_SENDER_DIR, top_name);

                              test_return = config_test_dir_write(current_settings, user_name, (char *)target_option->getopt_option.name, NULL, NULL, CONFIG_TEST_ERROR_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE_DELETE);
                              if (return_value)
                                return_value = test_return;

                              if ((sender_dir = opendir(user_name)) != NULL)
                                {
                                while ((sender_ent = readdir(sender_dir)) != NULL)
                                  if ((strcmp(sender_ent->d_name, DIR_CURRENT) != 0) &&
                                      (strcmp(sender_ent->d_name, DIR_PARENT) != 0))
                                    {
                                    snprintf(sender_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s", current_settings->current_options->graylist_dir[i], top_ent->d_name, domain_ent->d_name, user_ent->d_name, sender_ent->d_name);
                                    if (S_ISREG(config_test_file_type(user_name, sender_ent)))
                                      {
                                      SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TEST_GRAYLIST_SENDER_FILE, top_name);

                                      test_return = config_test_file_read_write(current_settings, sender_name, (char *)target_option->getopt_option.name, NULL, NULL, CONFIG_TEST_ERROR_FILE_READ_WRITE, NULL, 0, NULL);
                                      if (return_value)
                                        return_value = test_return;
                                      }
                                    else
                                      {
                                      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_GRAYLIST_SENDER_OTHER, target_option->getopt_option.name, config_test_file_type_string(user_name, sender_ent), sender_name);
                                      return_value = 0;
                                      }
                                    }

                                closedir(sender_dir);
                                }
                              else
                                {
                                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_GRAYLIST_SENDER_DIR, target_option->getopt_option.name, user_name, strerror(errno));
                                return_value = 0;
                                }
                              }
                            else
                              {
                              SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_GRAYLIST_USER_OTHER, target_option->getopt_option.name, config_test_file_type_string(domain_name, user_ent), user_name);
                              return_value = 0;
                              }
                            }

                        closedir(user_dir);
                        }
                      else
                        {
                        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_GRAYLIST_USER_DIR, target_option->getopt_option.name, domain_name, strerror(errno));
                        return_value = 0;
                        }
                      }
                    else
                      {
                      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_GRAYLIST_DOMAIN_OTHER, target_option->getopt_option.name, config_test_file_type_string(top_name, domain_ent), domain_name);
                      return_value = 0;
                      }
                    }

                closedir(domain_dir);
                }
              else
                {
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_GRAYLIST_DOMAIN_DIR, target_option->getopt_option.name, top_name, strerror(errno));
                return_value = 0;
                }
              }
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_GRAYLIST_TOP_OTHER, target_option->getopt_option.name, config_test_file_type_string(current_settings->current_options->graylist_dir[i], top_ent), top_name);
              return_value = 0;
              }
            }

        closedir(top_dir);

        if (accept_domain_list != NULL)
          for (k = 0; accept_domain_list[k] != NULL; k++)
            for (j = 0; accept_domain_list[k][j] != NULL; j++)
              if (accept_domain_list[k][j][0] != '\0')
                {
                if ((current_settings->current_options->graylist_level & GRAYLIST_LEVEL_MASK_CREATION) == GRAYLIST_LEVEL_FLAG_NO_CREATE)
                  SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_GRAYLIST_DOMAIN_MISSING, target_option->getopt_option.name, accept_domain_list[k][j]);
                else
                  SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_GRAYLIST_DOMAIN_CREATE, target_option->getopt_option.name, accept_domain_list[k][j]);
                }

        if (return_value == 1)
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_GRAYLIST, target_option->getopt_option.name, current_settings->current_options->graylist_dir[i]);
        }
      else
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_GRAYLIST_TOP_DIR, target_option->getopt_option.name, current_settings->current_options->graylist_dir[i], strerror(errno));
        return_value = 0;
        }
      }

  if (accept_domain_list != NULL)
    {
    for (i = 0; accept_domain_list[i] != NULL; i++)
      {
      for (j = 0; accept_domain_list[i][j] != NULL; j++)
        free(accept_domain_list[i][j]);

      free(accept_domain_list[i]);
      }

    free(accept_domain_list);
    }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_rdns_dir(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;
  int i;
  char ***dir_array;
  DIR *top_dir;
  DIR *tld_dir;
  DIR *letter_dir;
  DIR *sld_dir;
  struct dirent *top_ent;
  struct dirent *tld_ent;
  struct dirent *letter_ent;
  struct dirent *sld_ent;
  char top_name[MAX_BUF + 1];
  char tld_name[MAX_BUF + 1];
  char letter_name[MAX_BUF + 1];
  char sld_name[MAX_BUF + 1];
  char fqdn[MAX_BUF + 1];
  int top_count;
  int tld_count;
  int letter_count;
  int sld_count;
  int strlen_fqdn;
  int strlen_filename;

  return_value = 1;
  if (((dir_array = (*target_option->getter.get_string_array)(current_settings->current_options, 0)) != NULL) &&
      ((*dir_array) != NULL))
    for (i = 0; (*dir_array)[i] != NULL; i++)
      {
      SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_START_RDNS_DIR, target_option->getopt_option.name, (*dir_array)[i]);

      if ((top_dir = opendir((*dir_array)[i])) != NULL)
        {
        top_count = 0;
        while ((top_ent = readdir(top_dir)) != NULL)
          if ((strcmp(top_ent->d_name, DIR_CURRENT) != 0) &&
              (strcmp(top_ent->d_name, DIR_PARENT) != 0))
            {
            top_count++;
            snprintf(top_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s", (*dir_array)[i], top_ent->d_name);

            if (S_ISDIR(config_test_file_type((*dir_array)[i], top_ent)))
              {
              if ((tld_dir = opendir(top_name)) != NULL)
                {
                tld_count = 0;
                while ((tld_ent = readdir(tld_dir)) != NULL)
                  if ((strcmp(tld_ent->d_name, DIR_CURRENT) != 0) &&
                      (strcmp(tld_ent->d_name, DIR_PARENT) != 0))
                    {
                    tld_count++;
                    snprintf(tld_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s", (*dir_array)[i], top_ent->d_name, tld_ent->d_name);

                    if (S_ISDIR(config_test_file_type(top_name, tld_ent)))
                      {
                      if (strlen(tld_ent->d_name) != 1)
                        {
                        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_LETTER_DIR, target_option->getopt_option.name, tld_name);
                        return_value = 0;
                        }

                      if ((letter_dir = opendir(tld_name)) != NULL)
                        {
                        letter_count = 0;
                        while ((letter_ent = readdir(letter_dir)) != NULL)
                          if ((strcmp(letter_ent->d_name, DIR_CURRENT) != 0) &&
                              (strcmp(letter_ent->d_name, DIR_PARENT) != 0))
                            {
                            letter_count++;
                            snprintf(letter_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s", (*dir_array)[i], top_ent->d_name, tld_ent->d_name, letter_ent->d_name);

                            if (S_ISDIR(config_test_file_type(tld_name, letter_ent)))
                              {
                              if (tld_ent->d_name[0] != letter_ent->d_name[0])
                                {
                                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_LETTER_MISMATCH, target_option->getopt_option.name, letter_name);
                                return_value = 0;
                                }

                              if ((sld_dir = opendir(letter_name)) != NULL)
                                {
                                sld_count = 0;
                                while ((sld_ent = readdir(sld_dir)) != NULL)
                                  if ((strcmp(sld_ent->d_name, DIR_CURRENT) != 0) &&
                                      (strcmp(sld_ent->d_name, DIR_PARENT) != 0))
                                    {
                                    sld_count++;
                                    snprintf(sld_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s", (*dir_array)[i], top_ent->d_name, tld_ent->d_name, letter_ent->d_name, sld_ent->d_name);

                                    if (S_ISREG(config_test_file_type(letter_name, sld_ent)))
                                      {
                                      strlen_fqdn = SNPRINTF(fqdn, MAX_BUF, ".%s.%s", letter_ent->d_name, top_ent->d_name);
                                      strlen_filename = strlen(sld_ent->d_name);

                                      if ((((strlen_fqdn - 1) != strlen_filename) ||
                                           strcmp(fqdn + 1, sld_ent->d_name)) &&
                                          ((strlen_fqdn >= strlen_filename) ||
                                           strcmp(fqdn, sld_ent->d_name + (strlen_filename - strlen_fqdn))))
                                        {
                                        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_FQDN_MISMATCH, target_option->getopt_option.name, fqdn + 1, sld_name);
                                        return_value = 0;
                                        }
                                      }
                                    else
                                      {
                                      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_NON_FILE, target_option->getopt_option.name, config_test_file_type_string(letter_name, sld_ent), sld_name);
                                      return_value = 0;
                                      }
                                    }

                                if (sld_count == 0)
                                  {
                                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_NO_FILES, target_option->getopt_option.name, letter_name);
                                  return_value = 0;
                                  }

                                closedir(sld_dir);
                                }
                              else
                                {
                                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_OPENDIR, target_option->getopt_option.name, letter_name, strerror(errno));
                                return_value = 0;
                                }
                              }
                            else
                              {
                              SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_NON_DIR, target_option->getopt_option.name, config_test_file_type_string(tld_name, letter_ent), letter_name);
                              return_value = 0;
                              }
                            }

                        if (letter_count == 0)
                          {
                          SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_NO_FOLDERS, target_option->getopt_option.name, tld_name);
                          return_value = 0;
                          }

                        closedir(letter_dir);
                        }
                      else
                        {
                        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_OPENDIR, target_option->getopt_option.name, tld_name, strerror(errno));
                        return_value = 0;
                        }
                      }
                    else
                      {
                      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_NON_DIR, target_option->getopt_option.name, config_test_file_type_string(top_name, tld_ent), tld_name);
                      return_value = 0;
                      }
                    }

                if (tld_count == 0)
                  {
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_NO_FOLDERS, target_option->getopt_option.name, top_name);
                  return_value = 0;
                  }

                closedir(tld_dir);
                }
              else
                {
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_OPENDIR, target_option->getopt_option.name, top_name, strerror(errno));
                return_value = 0;
                }
              }
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_NON_DIR, target_option->getopt_option.name, config_test_file_type_string((*dir_array)[i], top_ent), top_name);
              return_value = 0;
              }
            }

        if (top_count == 0)
          {
          SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_NO_FOLDERS, target_option->getopt_option.name, (*dir_array)[i]);
          return_value = 0;
          }

        closedir(top_dir);

        if (return_value)
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_RDNS_DIR, target_option->getopt_option.name, (*dir_array)[i]);
        }
      else
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RDNS_OPENDIR, target_option->getopt_option.name, (*dir_array)[i], strerror(errno));
        return_value = 0;
        }
      }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_smtpauth(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  static char *environment_hostname[] = ENVIRONMENT_HOSTNAME;
  static int strlen_environment_hostname[] = STRLEN_ENVIRONMENT_HOSTNAME;
  int return_value;
  int test_return;
  int i;
  int j;
  struct stat tmp_stat;
  struct passwd *tmp_passwd;
  char tmp_name[MAX_BUF + 1];
  unsigned char ipad[MAX_BUF + 1];
  unsigned char opad[MAX_BUF + 1];
  unsigned char md5_result[16];
  unsigned char secret[64];
  unsigned char final[33];
  char challenge[MAX_BUF + 1];
  int strlen_challenge;
  int strlen_password;
  int encryption_supported;

  return_value = 1;

  if (current_settings->current_options->smtp_auth_command != NULL)
    {
    encryption_supported = 0;

    for (i = 0; current_settings->current_options->smtp_auth_command[i] != NULL; i++)
      {
      SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_SMTPAUTH_START, target_option->getopt_option.name, current_settings->current_options->smtp_auth_command[i]);

      for (j = 0; (current_settings->current_options->smtp_auth_command[i][j] != '\0') && !isspace((int)current_settings->current_options->smtp_auth_command[i][j]); j++);
      snprintf(tmp_name, MAX_BUF, "%.*s", j, current_settings->current_options->smtp_auth_command[i]);

      if ((stat(tmp_name, &tmp_stat) == 0) &&
          ((test_return = config_test_file_execute(current_settings, tmp_name, (char *)target_option->getopt_option.name, NULL, CONFIG_TEST_SUCCESS_EXECUTE, CONFIG_TEST_ERROR_EXECUTE, &tmp_stat))) == 1)
        {
        if (return_value)
          return_value = test_return;

        if (tmp_stat.st_uid != 0)
          {
          tmp_passwd = getpwuid(tmp_stat.st_uid);
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SMTPAUTH_OWNER_WARN, target_option->getopt_option.name, tmp_name, (tmp_passwd != NULL) ? tmp_passwd->pw_name : LOG_MISSING_DATA, tmp_stat.st_uid);
          endpwent();
          }
        else if ((tmp_stat.st_mode & S_ISUID) == 0)
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SMTPAUTH_SETUID_WARN, target_option->getopt_option.name, tmp_name);

        if ((current_settings->current_options->test_smtp_auth_username != NULL) &&
            (current_settings->current_options->test_smtp_auth_password != NULL))
          {
          SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_SMTPAUTH_RUN_PLAIN, target_option->getopt_option.name, current_settings->current_options->smtp_auth_command[i]);
          if (exec_checkpassword(current_settings, current_settings->current_options->smtp_auth_command[i], current_settings->current_options->test_smtp_auth_username, current_settings->current_options->test_smtp_auth_password, NULL))
            SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_SUCCESS_SMTPAUTH_PLAIN, target_option->getopt_option.name, current_settings->current_options->smtp_auth_command[i]);
          else
            {
            SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_FAILURE_SMTPAUTH_PLAIN, target_option->getopt_option.name, current_settings->current_options->smtp_auth_command[i]);
            return_value = 0;
            }

          if ((current_settings->current_options->local_server_name == NULL) &&
              (current_settings->current_options->local_server_name_file != NULL))
            read_file_first_line(current_settings, current_settings->current_options->local_server_name_file, &current_settings->current_options->local_server_name);

          if ((current_settings->current_options->local_server_name == NULL) &&
              (current_settings->current_options->local_server_name_command != NULL))
            exec_command(current_settings, current_settings->current_options->local_server_name_command, NULL, &current_settings->current_options->local_server_name, -1, NULL);

          if (current_settings->current_options->local_server_name == NULL)
            for (j = 0; environment_hostname[j] != NULL; j++)
              if ((current_settings->current_options->local_server_name = find_environment_variable(current_settings, current_settings->current_environment, environment_hostname[j], strlen_environment_hostname[j], NULL)) != NULL)
                break;

          for (j = 0; j < 64; j++)
            {
            ipad[j] = MD5_IPAD_BYTE;
            opad[j] = MD5_OPAD_BYTE;
            }

          if ((strlen_password = strlen(current_settings->current_options->test_smtp_auth_password)) > 64)
            {
            md5(secret, (unsigned char *)current_settings->current_options->test_smtp_auth_password, strlen_password);
            for (j = 16; j < 64; j++)
              secret[j] = '\0';
            }
          else
            {
            memcpy(secret, current_settings->current_options->test_smtp_auth_password, sizeof(char) * strlen_password);
            for (j = strlen_password; j < 64; j++)
              secret[j] = '\0';
            }

          for (j = 0; j < 64; j++)
            {
            ipad[j] ^= secret[j];
            opad[j] ^= secret[j];
            }

          strlen_challenge = SNPRINTF(challenge, MAX_BUF - 64, "<%ld.%ld@%s>", random(), (long)time(NULL), (current_settings->current_options->local_server_name != NULL) ? current_settings->current_options->local_server_name : MISSING_LOCAL_SERVER_NAME);
          for (j = 0; j < strlen_challenge; j++)
            ipad[j + 64] = challenge[j];

          md5(opad + 64, ipad, strlen_challenge + 64);
          md5(md5_result, opad, 80);

          for (j = 0; j < 16; j++)
            snprintf((char *)(final + (j * 2)), 33 - (j * 2), "%.2x", md5_result[j]);

          SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_SMTPAUTH_RUN_ENCRYPTED, target_option->getopt_option.name, current_settings->current_options->smtp_auth_command[i]);
          if (exec_checkpassword(current_settings, current_settings->current_options->smtp_auth_command[i], current_settings->current_options->test_smtp_auth_username, (char *)final, challenge))
            {
            SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_SUCCESS_SMTPAUTH_ENCRYPTED, target_option->getopt_option.name, current_settings->current_options->smtp_auth_command[i]);
            encryption_supported = 1;
            }
          else
            SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_FAILURE_SMTPAUTH_ENCRYPTED, target_option->getopt_option.name, current_settings->current_options->smtp_auth_command[i]);
          }
        }
      else
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_FILE_READ, target_option->getopt_option.name, tmp_name, strerror(errno));
        return_value = 0;
        }
      }

    switch (current_settings->current_options->smtp_auth_level & SMTP_AUTH_LEVEL_MASK)
      {
      case SMTP_AUTH_LEVEL_VALUE_NONE:
      case SMTP_AUTH_LEVEL_VALUE_OBSERVE:
        SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SMTPAUTH_UNUSED, config_test_find_integer_string(&target_option->validity.string_list, SMTP_AUTH_LEVEL_VALUE_ON_DEMAND | SMTP_AUTH_SET_VALUE_SET));
        break;
      case SMTP_AUTH_LEVEL_VALUE_ON_DEMAND:
      case SMTP_AUTH_LEVEL_VALUE_ALWAYS:
        if ((current_settings->current_options->test_smtp_auth_username != NULL) &&
            (current_settings->current_options->test_smtp_auth_password != NULL) &&
            (encryption_supported == 1))
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SMTPAUTH_SUGGEST_ENCRYPTED, config_test_find_integer_string(&target_option->validity.string_list, SMTP_AUTH_LEVEL_VALUE_ON_DEMAND_ENCRYPTED | SMTP_AUTH_SET_VALUE_SET), config_test_find_integer_string(&target_option->validity.string_list, SMTP_AUTH_LEVEL_VALUE_ALWAYS_ENCRYPTED | SMTP_AUTH_SET_VALUE_SET), config_test_find_integer_string(&target_option->validity.string_list, current_settings->current_options->smtp_auth_level));

        break;
      case SMTP_AUTH_LEVEL_VALUE_ON_DEMAND_ENCRYPTED:
      case SMTP_AUTH_LEVEL_VALUE_ALWAYS_ENCRYPTED:
        if ((current_settings->current_options->test_smtp_auth_username != NULL) &&
            (current_settings->current_options->test_smtp_auth_password != NULL) &&
            (encryption_supported == 0))
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SMTPAUTH_SUGGEST_PLAIN, config_test_find_integer_string(&target_option->validity.string_list, SMTP_AUTH_LEVEL_VALUE_ON_DEMAND | SMTP_AUTH_SET_VALUE_SET), config_test_find_integer_string(&target_option->validity.string_list, SMTP_AUTH_LEVEL_VALUE_ALWAYS | SMTP_AUTH_SET_VALUE_SET), config_test_find_integer_string(&target_option->validity.string_list, current_settings->current_options->smtp_auth_level));

        break;
      }
    }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_tls_certificate(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;

#ifdef HAVE_LIBSSL

  int test_result;

#endif /* HAVE_LIBSSL */

  return_value = 1;

#ifdef HAVE_LIBSSL

  if (current_settings->current_options->tls_certificate_file != NULL)
    {
    SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_START_TLS, target_option->getopt_option.name);

    test_result = config_test_file_read(current_settings, current_settings->current_options->tls_certificate_file, (char *)target_option->getopt_option.name, NULL, CONFIG_TEST_SUCCESS_FILE_READ, CONFIG_TEST_ERROR_FILE_READ, NULL, 0, NULL);
    if (return_value)
      return_value = test_result;

    if ((test_result = tls_test(current_settings)) == 1)
      SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_TLS, target_option->getopt_option.name);

    if (return_value)
      return_value = test_result;
    }

#else /* HAVE_LIBSSL */

  if (current_settings->current_options->tls_certificate_file != NULL)
    {
    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_TLS_CERT_DISABLED, target_option->getopt_option.name, current_settings->current_options->tls_certificate_file);
    return_value = 0;
    }

#endif /* HAVE_LIBSSL */

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_tls_privatekey(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;

#ifdef HAVE_LIBSSL

  int test_result;

  return_value = 1;

  if (current_settings->current_options->tls_privatekey_file != NULL)
    {
    test_result = config_test_file_read(current_settings, current_settings->current_options->tls_privatekey_file, (char *)target_option->getopt_option.name, CONFIG_TEST_START_TLS_PRIVATEKEY, CONFIG_TEST_SUCCESS_FILE_READ, CONFIG_TEST_ERROR_FILE_READ, NULL, 0, NULL);
    if (return_value)
      return_value = test_result;
    }

#else /* HAVE_LIBSSL */

  return_value = 1;

  if (current_settings->current_options->tls_privatekey_file != NULL)
    {
    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_TLS_PRIVATEKEY_DISABLED, target_option->getopt_option.name, current_settings->current_options->tls_privatekey_file);
    return_value = 0;
    }

#endif /* HAVE_LIBSSL */

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_tls_password(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;

  return_value = 1;

#ifndef HAVE_LIBSSL

  if (current_settings->current_options->tls_privatekey_password != NULL)
    {
    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_TLS_PASSWORD_DISABLED, target_option->getopt_option.name);
    return_value = 0;
    }

#endif /* HAVE_LIBSSL */

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_tls_dhparams(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;

#ifdef HAVE_LIBSSL

  int test_result;

  return_value = 1;

  if (current_settings->current_options->tls_dhparams_file != NULL)
    {
    test_result = config_test_file_read(current_settings, current_settings->current_options->tls_dhparams_file, (char *)target_option->getopt_option.name, CONFIG_TEST_START_TLS_DHPARAMS, CONFIG_TEST_SUCCESS_FILE_READ, CONFIG_TEST_ERROR_FILE_READ, NULL, 0, NULL);
    if (return_value)
      return_value = test_result;
    }

#else /* HAVE_LIBSSL */

  return_value = 1;

  if (current_settings->current_options->tls_dhparams_file != NULL)
    {
    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_TLS_DHPARAMS_DISABLED, target_option->getopt_option.name, current_settings->current_options->tls_dhparams_file);
    return_value = 0;
    }

#endif /* HAVE_LIBSSL */

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_spamdyke_binary(struct filter_settings *current_settings, int argc, char *argv[])
  {
  int return_value;
  struct stat tmp_stat;
  char *path;
  char *tmp_start;
  char *tmp_end;
  char new_filename[MAX_BUF + 1];
  int found_match;

  return_value = 0;

  if (argv[0] != NULL)
    {
    if (strchr(argv[0], DIR_DELIMITER) != NULL)
      {
      if (stat(argv[0], &tmp_stat) == 0)
        {
        if ((tmp_stat.st_uid != 0) ||
            ((tmp_stat.st_mode & S_ISUID) == 0))
          {
          SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_SUCCESS_SETUID, argv[0]);
          return_value = 1;
          }
        else
          SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_SETUID, argv[0]);
        }
      else
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_SETUID_STAT, argv[0], strerror(errno));
      }
    else
      {
      found_match = 0;

      if (((path = find_environment_variable(current_settings, current_settings->current_environment, ENVIRONMENT_PATH, STRLEN(ENVIRONMENT_PATH), NULL)) == NULL) ||
          (path[0] == '\0'))
        {
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_PATH_DEFAULT, DEFAULT_PATH);
        path = DEFAULT_PATH;
        }

      tmp_start = path;
      tmp_end = NULL;
      while (tmp_start != NULL)
        {
        if ((tmp_end = strchr(tmp_start, ':')) != NULL)
          {
          snprintf(new_filename, MAX_BUF, "%.*s" DIR_DELIMITER_STR "%s", (int)(tmp_end - tmp_start), tmp_start, argv[0]);
          tmp_start = tmp_end + 1;
          }
        else
          {
          snprintf(new_filename, MAX_BUF, "%s" DIR_DELIMITER_STR "%s", tmp_start, argv[0]);
          tmp_start = NULL;
          }

        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_PATH_SEARCH, new_filename);

        if ((stat(new_filename, &tmp_stat) == 0) &&
            config_test_file_execute(current_settings, new_filename, CONFIG_TEST_OPTION_NAME_BINARY, CONFIG_TEST_START_EXECUTE, CONFIG_TEST_SUCCESS_EXECUTE, NULL, &tmp_stat))
          {
          if ((tmp_stat.st_uid != 0) ||
              ((tmp_stat.st_mode & S_ISUID) == 0))
            {
            SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_SUCCESS_SETUID, new_filename);
            return_value = 1;
            }
          else
            SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_SETUID, new_filename);

          found_match = 1;
          break;
          }
        }

      if (!found_match)
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_SETUID_SEARCH, argv[0]);
      }
    }
  else
    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_SETUID_FILENAME);

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_child_capabilities(struct filter_settings *current_settings)
  {
  static struct expect_send patch_test[] = CONFIG_TEST_PATCH_SCRIPT;
  int return_value;
  int i;
  char child_output[MAX_BUF + 1];
  int strlen_child_output;
  char *tmp_ptr;

  return_value = 0;

  if (current_settings->child_argv != NULL)
    {
    SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_PATCH_RUN, current_settings->child_argv[0]);

    tmp_ptr = child_output;
    if ((strlen_child_output = exec_command_argv(current_settings, current_settings->child_argv[0], current_settings->child_argv, patch_test, &tmp_ptr, MAX_BUF, NULL)) > 0)
      {
      return_value = 1;

      for (i = 0; i < strlen_child_output; i++)
        child_output[i] = tolower((int)child_output[i]);

      if (((tmp_ptr = strstr(child_output, CONFIG_TEST_PATCH_TLS)) != NULL) &&
          ((((tmp_ptr - child_output) >= STRLEN(CONFIG_TEST_PATCH_SUCCESS_CONTINUATION)) &&
            !strncmp(tmp_ptr - STRLEN(CONFIG_TEST_PATCH_SUCCESS_CONTINUATION), CONFIG_TEST_PATCH_SUCCESS_CONTINUATION, STRLEN(CONFIG_TEST_PATCH_SUCCESS_CONTINUATION))) ||
           (((tmp_ptr - child_output) >= STRLEN(CONFIG_TEST_PATCH_SUCCESS_END)) &&
            !strncmp(tmp_ptr - STRLEN(CONFIG_TEST_PATCH_SUCCESS_END), CONFIG_TEST_PATCH_SUCCESS_END, STRLEN(CONFIG_TEST_PATCH_SUCCESS_END)))))

#ifdef HAVE_LIBSSL

        if ((current_settings->current_options->tls_level != TLS_LEVEL_NONE) &&
            (current_settings->current_options->tls_certificate_file != NULL))
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_TLS, current_settings->child_argv[0]);
        else
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_TLS_FLAG, current_settings->child_argv[0]);
      else
        if ((current_settings->current_options->tls_level != TLS_LEVEL_NONE) &&
            (current_settings->current_options->tls_certificate_file != NULL))
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_PATCH_TLS, current_settings->child_argv[0]);
        else
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_PATCH_TLS_FLAG, current_settings->child_argv[0]);

#else /* HAVE_LIBSSL */

        if ((current_settings->current_options->tls_level != TLS_LEVEL_NONE) &&
            (current_settings->current_options->tls_certificate_file != NULL))
          {
          SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_SUCCESS_PATCH_TLS_NO_TLS, current_settings->child_argv[0]);
          return_value = 0;
          }
        else
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_TLS_FLAG_NO_TLS, current_settings->child_argv[0]);
      else
        if ((current_settings->current_options->tls_level != TLS_LEVEL_NONE) &&
            (current_settings->current_options->tls_certificate_file != NULL))
          {
          SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_PATCH_TLS_NO_TLS, current_settings->child_argv[0]);
          return_value = 0;
          }
        else
          SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_PATCH_TLS_FLAG_NO_TLS, current_settings->child_argv[0]);

#endif /* HAVE_LIBSSL */

      if (((tmp_ptr = strstr(child_output, CONFIG_TEST_PATCH_SMTP_AUTH)) != NULL) &&
          ((((tmp_ptr - child_output) >= STRLEN(CONFIG_TEST_PATCH_SUCCESS_CONTINUATION)) &&
            !strncmp(tmp_ptr - STRLEN(CONFIG_TEST_PATCH_SUCCESS_CONTINUATION), CONFIG_TEST_PATCH_SUCCESS_CONTINUATION, STRLEN(CONFIG_TEST_PATCH_SUCCESS_CONTINUATION))) ||
           (((tmp_ptr - child_output) >= STRLEN(CONFIG_TEST_PATCH_SUCCESS_END)) &&
            !strncmp(tmp_ptr - STRLEN(CONFIG_TEST_PATCH_SUCCESS_END), CONFIG_TEST_PATCH_SUCCESS_END, STRLEN(CONFIG_TEST_PATCH_SUCCESS_END)))))
        switch (current_settings->current_options->smtp_auth_level & SMTP_AUTH_LEVEL_MASK)
          {
          case SMTP_AUTH_LEVEL_VALUE_NONE:
            if (current_settings->current_options->smtp_auth_command == NULL)
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_NONE, current_settings->child_argv[0]);
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_NONE_FLAG, current_settings->child_argv[0]);
              return_value = 0;
              }

            break;
          case SMTP_AUTH_LEVEL_VALUE_OBSERVE:
            if (current_settings->current_options->smtp_auth_command == NULL)
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_OBSERVE, current_settings->child_argv[0]);
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_OBSERVE_FLAG, current_settings->child_argv[0]);
              return_value = 0;
              }

            break;
          case SMTP_AUTH_LEVEL_VALUE_ON_DEMAND:
          case SMTP_AUTH_LEVEL_VALUE_ON_DEMAND_ENCRYPTED:
            if ((current_settings->current_options->smtp_auth_command != NULL) &&
                ((current_settings->current_options->qmail_rcpthosts_file != NULL) ||
                 (current_settings->current_options->qmail_morercpthosts_cdb != NULL)))
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_DEMAND, current_settings->child_argv[0], current_settings->child_argv[0]);
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_DEMAND_FLAG, current_settings->child_argv[0]);
              return_value = 0;
              }

            break;
          case SMTP_AUTH_LEVEL_VALUE_ALWAYS:
          case SMTP_AUTH_LEVEL_VALUE_ALWAYS_ENCRYPTED:
            if ((current_settings->current_options->smtp_auth_command != NULL) &&
                ((current_settings->current_options->qmail_rcpthosts_file != NULL) ||
                 (current_settings->current_options->qmail_morercpthosts_cdb != NULL)))
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_ALWAYS, current_settings->child_argv[0]);
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_ALWAYS_FLAG, current_settings->child_argv[0]);
              return_value = 0;
              }

            break;
          }
      else
        switch (current_settings->current_options->smtp_auth_level & SMTP_AUTH_LEVEL_MASK)
          {
          case SMTP_AUTH_LEVEL_VALUE_NONE:
            if (current_settings->current_options->smtp_auth_command == NULL)
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_NONE, current_settings->child_argv[0]);
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_NONE_FLAG, current_settings->child_argv[0]);
              return_value = 0;
              }

            break;
          case SMTP_AUTH_LEVEL_VALUE_OBSERVE:
            if (current_settings->current_options->smtp_auth_command == NULL)
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_OBSERVE, current_settings->child_argv[0]);
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_OBSERVE_FLAG, current_settings->child_argv[0]);
              return_value = 0;
              }

            break;
          case SMTP_AUTH_LEVEL_VALUE_ON_DEMAND:
          case SMTP_AUTH_LEVEL_VALUE_ON_DEMAND_ENCRYPTED:
            if ((current_settings->current_options->smtp_auth_command != NULL) &&
                ((current_settings->current_options->qmail_rcpthosts_file != NULL) ||
                 (current_settings->current_options->qmail_morercpthosts_cdb != NULL)))
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_DEMAND, current_settings->child_argv[0], current_settings->child_argv[0]);
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_DEMAND_FLAG, current_settings->child_argv[0]);
              return_value = 0;
              }

            break;
          case SMTP_AUTH_LEVEL_VALUE_ALWAYS:
          case SMTP_AUTH_LEVEL_VALUE_ALWAYS_ENCRYPTED:
            if ((current_settings->current_options->smtp_auth_command != NULL) &&
                ((current_settings->current_options->qmail_rcpthosts_file != NULL) ||
                 (current_settings->current_options->qmail_morercpthosts_cdb != NULL)))
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_ALWAYS, current_settings->child_argv[0]);
            else
              {
              SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_ALWAYS_FLAG, current_settings->child_argv[0]);
              return_value = 0;
              }

            break;
          }
      }
    else
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_PATCH_NO_OUTPUT, current_settings->child_argv[0]);
    }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_relay_level(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;

  return_value = 1;

  switch (current_settings->current_options->relay_level)
    {
    case RELAY_LEVEL_NO_RELAY:
      if (((current_settings->current_options->qmail_morercpthosts_cdb == NULL) ||
           (current_settings->current_options->qmail_morercpthosts_cdb[0] == NULL)) &&
          ((current_settings->current_options->qmail_rcpthosts_file == NULL) ||
           (current_settings->current_options->qmail_rcpthosts_file[0] == NULL)))
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RELAY_NO_RELAY_MISSING_LOCAL, target_option->getopt_option.name);
        return_value = 0;
        }

      break;
    case RELAY_LEVEL_NORMAL:
      if (((current_settings->current_options->qmail_morercpthosts_cdb == NULL) ||
           (current_settings->current_options->qmail_morercpthosts_cdb[0] == NULL)) &&
          ((current_settings->current_options->qmail_rcpthosts_file == NULL) ||
           (current_settings->current_options->qmail_rcpthosts_file[0] == NULL)))
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_RELAY_NORMAL_MISSING_LOCAL, target_option->getopt_option.name);
        return_value = 0;
        }

      break;
    case RELAY_LEVEL_ALLOW_ALL:
      break;
    }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_options(struct filter_settings *current_settings)
  {
  int return_value;
  int i;
  int j;
  int k;
  int line_recommendation;
  char *failure_overrecommendation_message;
  union
    {
    int *integer_ptr;
    char **string_ptr;
    char ***string_array_ptr;
    } ptr;
  char tmp_name[MAX_BUF + 1];

  return_value = 1;

  for (i = 0; current_settings->option_list[i].value_type != CONFIG_TYPE_NONE; i++)
    {
    line_recommendation = 0;
    failure_overrecommendation_message = NULL;

    if (current_settings->option_list[i].test_function != NULL)
      {
      if (!(*current_settings->option_list[i].test_function)(current_settings, current_settings->option_list + i))
        {
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
        return_value = 0;
        }
      }
    else
      switch (current_settings->option_list[i].value_type)
        {
        case CONFIG_TYPE_OPTION_ARRAY:
          if ((current_settings->option_list[i].getter.get_string_array != NULL) &&
              ((ptr.string_array_ptr = (*current_settings->option_list[i].getter.get_string_array)(current_settings->current_options, 0)) != NULL) &&
              (*ptr.string_array_ptr != NULL))
            {
            for (j = 0; (*(ptr.string_array_ptr))[j] != NULL; j++);
            if (j > CONFIG_TEST_OPTION_ARRAY_LIMIT)
              SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_OPTION_ARRAY, current_settings->option_list[i].getopt_option.name, j);
            }

          break;
        case CONFIG_TYPE_FILE_NOT_DIR_SINGLETON:
          line_recommendation = CONFIG_TEST_FILE_LINE_RECOMMENDATION;
          failure_overrecommendation_message = CONFIG_TEST_ERROR_FILE_OVERRECOMMENDATION;
        case CONFIG_TYPE_FILE_SINGLETON:
          if ((current_settings->option_list[i].getter.get_string != NULL) &&
              ((ptr.string_ptr = (*current_settings->option_list[i].getter.get_string)(current_settings->current_options, 0)) != NULL) &&
              (*ptr.string_ptr != NULL))
            switch (current_settings->option_list[i].access_type)
              {
              case CONFIG_ACCESS_READ_ONLY:
                if (!config_test_file_read(current_settings, *ptr.string_ptr, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_FILE_READ, CONFIG_TEST_SUCCESS_FILE_READ, CONFIG_TEST_ERROR_FILE_READ, CONFIG_TEST_ERROR_FILE_OVERLENGTH, line_recommendation, failure_overrecommendation_message))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                  return_value = 0;
                  }

                break;
              case CONFIG_ACCESS_WRITE_ONLY:
                if (!config_test_file_write(current_settings, *ptr.string_ptr, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_FILE_WRITE, CONFIG_TEST_SUCCESS_FILE_WRITE, CONFIG_TEST_ERROR_FILE_WRITE))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                  return_value = 0;
                  }

                break;
              case CONFIG_ACCESS_READ_WRITE:
                if (!config_test_file_read_write(current_settings, *ptr.string_ptr, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_FILE_READ_WRITE, CONFIG_TEST_SUCCESS_FILE_READ_WRITE, CONFIG_TEST_ERROR_FILE_READ_WRITE, CONFIG_TEST_ERROR_FILE_OVERLENGTH, line_recommendation, failure_overrecommendation_message))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                  return_value = 0;
                  }

                break;
              case CONFIG_ACCESS_EXECUTE:
                if (!config_test_file_execute(current_settings, *ptr.string_ptr, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_EXECUTE, CONFIG_TEST_SUCCESS_EXECUTE, CONFIG_TEST_ERROR_EXECUTE, NULL))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                  return_value = 0;
                  }

                break;
              default:
                break;
              }

          break;
        case CONFIG_TYPE_FILE_NOT_DIR_ARRAY:
          line_recommendation = CONFIG_TEST_FILE_LINE_RECOMMENDATION;
          failure_overrecommendation_message = CONFIG_TEST_ERROR_FILE_OVERRECOMMENDATION;
        case CONFIG_TYPE_FILE_ARRAY:
          if ((current_settings->option_list[i].getter.get_string_array != NULL) &&
              ((ptr.string_array_ptr = (*current_settings->option_list[i].getter.get_string_array)(current_settings->current_options, 0)) != NULL) &&
              (*ptr.string_array_ptr != NULL))
            switch (current_settings->option_list[i].access_type)
              {
              case CONFIG_ACCESS_READ_ONLY:
                for (j = 0; (*ptr.string_array_ptr)[j] != NULL; j++)
                  if (!config_test_file_read(current_settings, (*ptr.string_array_ptr)[j], (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_FILE_READ, CONFIG_TEST_SUCCESS_FILE_READ, CONFIG_TEST_ERROR_FILE_READ, CONFIG_TEST_ERROR_FILE_OVERLENGTH, line_recommendation, failure_overrecommendation_message))
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                    return_value = 0;
                    }

                break;
              case CONFIG_ACCESS_WRITE_ONLY:
                for (j = 0; (*ptr.string_array_ptr)[j] != NULL; j++)
                  if (!config_test_file_write(current_settings, (*ptr.string_array_ptr)[j], (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_FILE_WRITE, CONFIG_TEST_SUCCESS_FILE_WRITE, CONFIG_TEST_ERROR_FILE_WRITE))
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                    return_value = 0;
                    }

                break;
              case CONFIG_ACCESS_READ_WRITE:
                for (j = 0; (*ptr.string_array_ptr)[j] != NULL; j++)
                  if (!config_test_file_read_write(current_settings, (*ptr.string_array_ptr)[j], (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_FILE_READ_WRITE, CONFIG_TEST_SUCCESS_FILE_READ_WRITE, CONFIG_TEST_ERROR_FILE_READ_WRITE, CONFIG_TEST_ERROR_FILE_OVERLENGTH, line_recommendation, failure_overrecommendation_message))
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                    return_value = 0;
                    }

                break;
              case CONFIG_ACCESS_EXECUTE:
                for (j = 0; (*ptr.string_array_ptr)[j] != NULL; j++)
                  if (!config_test_file_execute(current_settings, (*ptr.string_array_ptr)[j], (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_EXECUTE, CONFIG_TEST_SUCCESS_EXECUTE, CONFIG_TEST_ERROR_EXECUTE, NULL))
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                    return_value = 0;
                    }

                break;
              default:
                break;
              }

          break;
        case CONFIG_TYPE_DIR_SINGLETON:
          if ((current_settings->option_list[i].getter.get_string != NULL) &&
              ((ptr.string_ptr = (*current_settings->option_list[i].getter.get_string)(current_settings->current_options, 0)) != NULL) &&
              (*ptr.string_ptr != NULL))
            switch (current_settings->option_list[i].access_type)
              {
              case CONFIG_ACCESS_READ_ONLY:
                if (!config_test_dir_read(current_settings, *ptr.string_ptr, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_DIR_READ, CONFIG_TEST_SUCCESS_DIR_READ, CONFIG_TEST_ERROR_DIR_READ))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                  return_value = 0;
                  }

                break;
              case CONFIG_ACCESS_WRITE_ONLY:
                if (!config_test_dir_write(current_settings, *ptr.string_ptr, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_DIR_WRITE, CONFIG_TEST_SUCCESS_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE_DELETE))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                  return_value = 0;
                  }

                break;
              case CONFIG_ACCESS_READ_WRITE:
                if (!config_test_dir_read(current_settings, *ptr.string_ptr, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_DIR_READ, CONFIG_TEST_SUCCESS_DIR_READ, CONFIG_TEST_ERROR_DIR_READ))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                  return_value = 0;
                  }

                if (!config_test_dir_write(current_settings, *ptr.string_ptr, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_DIR_WRITE, CONFIG_TEST_SUCCESS_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE_DELETE))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                  return_value = 0;
                  }

                break;
              case CONFIG_ACCESS_EXECUTE:
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_BAD_CONFIG_DIR_EXEC, (char *)current_settings->option_list[i].getopt_option.name);
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                return_value = 0;

                break;
              default:
                break;
              }

          break;
        case CONFIG_TYPE_DIR_ARRAY:
          if ((current_settings->option_list[i].getter.get_string_array != NULL) &&
              ((ptr.string_array_ptr = (*current_settings->option_list[i].getter.get_string_array)(current_settings->current_options, 0)) != NULL) &&
              (*ptr.string_array_ptr != NULL))
            switch (current_settings->option_list[i].access_type)
              {
              case CONFIG_ACCESS_READ_ONLY:
                for (j = 0; (*ptr.string_array_ptr)[j] != NULL; j++)
                  if (!config_test_dir_read(current_settings, (*ptr.string_array_ptr)[j], (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_DIR_READ, CONFIG_TEST_SUCCESS_DIR_READ, CONFIG_TEST_ERROR_DIR_READ))
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                    return_value = 0;
                    }

                break;
              case CONFIG_ACCESS_WRITE_ONLY:
                for (j = 0; (*ptr.string_array_ptr)[j] != NULL; j++)
                  if (config_test_dir_write(current_settings, (*ptr.string_array_ptr)[j], (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_DIR_WRITE, CONFIG_TEST_SUCCESS_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE_DELETE))
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                    return_value = 0;
                    }

                break;
              case CONFIG_ACCESS_READ_WRITE:
                for (j = 0; (*ptr.string_array_ptr)[j] != NULL; j++)
                  {
                  if (!config_test_dir_read(current_settings, (*ptr.string_array_ptr)[j], (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_DIR_READ, CONFIG_TEST_SUCCESS_DIR_READ, CONFIG_TEST_ERROR_DIR_READ))
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                    return_value = 0;
                    }

                  if (!config_test_dir_write(current_settings, (*ptr.string_array_ptr)[j], (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_DIR_WRITE, CONFIG_TEST_SUCCESS_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE, CONFIG_TEST_ERROR_DIR_WRITE_DELETE))
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                    return_value = 0;
                    }
                  }

                break;
              case CONFIG_ACCESS_EXECUTE:
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_BAD_CONFIG_DIR_EXEC, (char *)current_settings->option_list[i].getopt_option.name);
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                return_value = 0;

                break;
              default:
                break;
              }

          break;
        case CONFIG_TYPE_COMMAND_SINGLETON:
          if ((current_settings->option_list[i].getter.get_string != NULL) &&
              ((ptr.string_ptr = (*current_settings->option_list[i].getter.get_string)(current_settings->current_options, 0)) != NULL) &&
              (*ptr.string_ptr != NULL))
            switch (current_settings->option_list[i].access_type)
              {
              case CONFIG_ACCESS_READ_ONLY:
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_BAD_CONFIG_CMD_READ, (char *)current_settings->option_list[i].getopt_option.name);
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                return_value = 0;

                break;
              case CONFIG_ACCESS_WRITE_ONLY:
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_BAD_CONFIG_CMD_WRITE, (char *)current_settings->option_list[i].getopt_option.name);
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                return_value = 0;

                break;
              case CONFIG_ACCESS_READ_WRITE:
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_BAD_CONFIG_CMD_READ_WRITE, (char *)current_settings->option_list[i].getopt_option.name);
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                return_value = 0;

                break;
              case CONFIG_ACCESS_EXECUTE:
                for (k = 0; ((*ptr.string_ptr)[k] != '\0') && !isspace((int)(*ptr.string_ptr)[k]); k++);
                snprintf(tmp_name, MAX_BUF, "%.*s", k, *ptr.string_ptr);

                if (!config_test_file_execute(current_settings, tmp_name, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_EXECUTE, CONFIG_TEST_SUCCESS_EXECUTE, CONFIG_TEST_ERROR_EXECUTE, NULL))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                  return_value = 0;
                  }

                break;
              default:
                break;
              }

          break;
        case CONFIG_TYPE_COMMAND_ARRAY:
          if ((current_settings->option_list[i].getter.get_string_array != NULL) &&
              ((ptr.string_array_ptr = (*current_settings->option_list[i].getter.get_string_array)(current_settings->current_options, 0)) != NULL) &&
              (*ptr.string_array_ptr != NULL))
            switch (current_settings->option_list[i].access_type)
              {
              case CONFIG_ACCESS_READ_ONLY:
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_BAD_CONFIG_CMD_READ, (char *)current_settings->option_list[i].getopt_option.name);
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                return_value = 0;

                break;
              case CONFIG_ACCESS_WRITE_ONLY:
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_BAD_CONFIG_CMD_WRITE, (char *)current_settings->option_list[i].getopt_option.name);
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                return_value = 0;

                break;
              case CONFIG_ACCESS_READ_WRITE:
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_BAD_CONFIG_CMD_READ_WRITE, (char *)current_settings->option_list[i].getopt_option.name);
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                return_value = 0;

                break;
              case CONFIG_ACCESS_EXECUTE:
                for (j = 0; (*ptr.string_array_ptr)[j] != NULL; j++)
                  {
                  for (k = 0; ((*ptr.string_array_ptr)[j][k] != '\0') && !isspace((int)(*ptr.string_array_ptr)[j][k]); k++);
                  snprintf(tmp_name, MAX_BUF, "%.*s", k, (*ptr.string_array_ptr)[j]);

                  if (!config_test_file_execute(current_settings, tmp_name, (char *)current_settings->option_list[i].getopt_option.name, CONFIG_TEST_START_EXECUTE, CONFIG_TEST_SUCCESS_EXECUTE, CONFIG_TEST_ERROR_EXECUTE, NULL))
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE, current_settings->option_list[i].getopt_option.name);
                    return_value = 0;
                    }
                  }

                break;
              default:
                break;
              }

          break;
        default:
          break;
        }
    }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test(struct filter_settings *current_settings, int argc, char *argv[])
  {
  static char *config_test_environment_remote_ip[] = CONFIG_TEST_ENVIRONMENT_REMOTE_IP;
  static int config_test_strlen_environment_remote_ip[] = CONFIG_TEST_STRLEN_ENVIRONMENT_REMOTE_IP;
  int return_value;
  int i;
  int j;
  int num_remote_ip;
  int found_local_port;
  int *found_remote_ip;
  int found_remote_name;
  int len_envp;
  int missing_envp;
  uid_t tmp_uid;
  gid_t tmp_gid;
  struct passwd *tmp_passwd;
  struct group *tmp_group;
  char **new_envp;
  char **saved_envp;

  return_value = 1;
  found_remote_ip = NULL;
  new_envp = NULL;
  saved_envp = current_settings->current_environment;

  usage(current_settings, USAGE_LEVEL_SHORT, NULL);

  current_settings->current_options->log_level = MAXVAL(LOG_LEVEL_ERROR, current_settings->current_options->log_level);
  current_settings->current_options->log_target = LOG_USE_CONFIG_TEST;
  SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_START, NULL);

  for (i = 1; current_settings->option_list[i].value_type != CONFIG_TYPE_NONE; i++)
    if (strcmp(current_settings->option_list[i - 1].getopt_option.name, current_settings->option_list[i].getopt_option.name) >= 0)
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, LOG_ERROR_OPTION_LIST_ORDER, current_settings->option_list[i - 1].getopt_option.name, current_settings->option_list[i].getopt_option.name);

  /* Setup the environment array for running child processes */
  for (num_remote_ip = 0; config_test_environment_remote_ip[num_remote_ip] != NULL; num_remote_ip++);
  if ((found_remote_ip = (int *)malloc(sizeof(int) * num_remote_ip)) != NULL)
    {
    found_local_port = 0;
    for (i = 0; i < num_remote_ip; i++)
      found_remote_ip[i] = 0;
    found_remote_name = 0;

    if (current_settings->current_environment != NULL)
      {
      for (len_envp = 0; current_settings->current_environment[len_envp] != NULL; len_envp++)
        if (!strncmp(current_settings->current_environment[len_envp], ENVIRONMENT_LOCAL_PORT, STRLEN(ENVIRONMENT_LOCAL_PORT)))
          found_local_port = 1;
        else if (!strncmp(current_settings->current_environment[len_envp], ENVIRONMENT_REMOTE_NAME, STRLEN(ENVIRONMENT_REMOTE_NAME)))
          found_remote_name = 1;
        else
          for (j = 0; j < num_remote_ip; j++)
            if (!strncmp(current_settings->current_environment[len_envp], config_test_environment_remote_ip[j], config_test_strlen_environment_remote_ip[j]))
              {
              found_remote_ip[j] = 1;
              break;
              }
      }
    else
      len_envp = 0;

    missing_envp = (found_local_port ? 0 : 1) + (found_remote_name ? 0 : 1);
    for (j = 0; j < num_remote_ip; j++)
      if (!found_remote_ip[j])
        missing_envp++;

    if (missing_envp > 0)
      {
      if ((new_envp = (char **)malloc(sizeof(char *) * (len_envp + missing_envp + 1))) != NULL)
        {
        if (current_settings->current_environment != NULL)
          memcpy(new_envp, current_settings->current_environment, sizeof(char *) * len_envp);
        new_envp[len_envp] = NULL;

        if (!found_local_port)
          {
          if ((new_envp[len_envp] = malloc(sizeof(char) * (STRLEN(CONFIG_TEST_ENVIRONMENT_LOCAL_PORT) + 1))) != NULL)
            {
            memcpy(new_envp[len_envp], CONFIG_TEST_ENVIRONMENT_LOCAL_PORT, sizeof(char) * STRLEN(CONFIG_TEST_ENVIRONMENT_LOCAL_PORT));
            new_envp[len_envp][STRLEN(CONFIG_TEST_ENVIRONMENT_LOCAL_PORT)] = '\0';
            len_envp++;
            new_envp[len_envp] = NULL;
            }
          else
            {
            SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char) * (STRLEN(CONFIG_TEST_ENVIRONMENT_LOCAL_PORT) + 1)));
            return_value = 0;
            }
          }

        if ((return_value == 1) &&
            !found_remote_name)
          {
          if ((new_envp[len_envp] = malloc(sizeof(char) * (STRLEN(CONFIG_TEST_ENVIRONMENT_REMOTE_NAME) + 1))) != NULL)
            {
            memcpy(new_envp[len_envp], CONFIG_TEST_ENVIRONMENT_REMOTE_NAME, sizeof(char) * STRLEN(CONFIG_TEST_ENVIRONMENT_REMOTE_NAME));
            new_envp[len_envp][STRLEN(CONFIG_TEST_ENVIRONMENT_REMOTE_NAME)] = '\0';
            len_envp++;
            new_envp[len_envp] = NULL;
            }
          else
            {
            SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char) * (STRLEN(CONFIG_TEST_ENVIRONMENT_REMOTE_NAME) + 1)));
            return_value = 0;
            }
          }

        if (return_value == 1)
          for (j = 0; j < num_remote_ip; j++)
            if (!found_remote_ip[j])
              {
              if ((new_envp[len_envp] = malloc(sizeof(char) * (config_test_strlen_environment_remote_ip[j] + 1))) != NULL)
                {
                memcpy(new_envp[len_envp], config_test_environment_remote_ip[j], sizeof(char) * config_test_strlen_environment_remote_ip[j]);
                new_envp[len_envp][config_test_strlen_environment_remote_ip[j]] = '\0';
                len_envp++;
                new_envp[len_envp] = NULL;
                }
              else
                {
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char) * (config_test_strlen_environment_remote_ip[j] + 1)));
                return_value = 0;
                break;
                }
              }
        }
      else
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char *) * (len_envp + 2)));
        return_value = 0;
        }
      }

    if (new_envp != NULL)
      current_settings->current_environment = new_envp;

    free(found_remote_ip);
    }
  else
    {
    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(int) * (num_remote_ip)));
    return_value = 0;
    }

  /* Check user and group IDs */
  tmp_gid = getegid();
  tmp_group = getgrgid(tmp_gid);
  tmp_uid = geteuid();
  tmp_passwd = getpwuid(tmp_uid);

  if (tmp_uid != 0)
    if (current_settings->current_options->run_user != NULL)
      SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_SUCCESS_UID, (tmp_passwd != NULL) ? tmp_passwd->pw_name : LOG_MISSING_DATA, tmp_uid, (tmp_group != NULL) ? tmp_group->gr_name : LOG_MISSING_DATA, tmp_gid);
    else
      SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_WARNING_UID, (tmp_passwd != NULL) ? tmp_passwd->pw_name : LOG_MISSING_DATA, tmp_uid, (tmp_group != NULL) ? tmp_group->gr_name : LOG_MISSING_DATA, tmp_gid);
  else
    SPAMDYKE_LOG_CONFIG_TEST_INFO(current_settings, CONFIG_TEST_ERROR_UID, (tmp_passwd != NULL) ? tmp_passwd->pw_name : LOG_MISSING_DATA, tmp_uid, (tmp_group != NULL) ? tmp_group->gr_name : LOG_MISSING_DATA, tmp_gid);

  endpwent();

  if (!config_test_spamdyke_binary(current_settings, argc, argv))
    return_value = 0;

  if (!config_test_child_capabilities(current_settings))
    return_value = 0;

  if (!config_test_options(current_settings))
    return_value = 0;

  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, return_value ? CONFIG_TEST_SUCCESS : CONFIG_TEST_ERROR);

  free_environment(current_settings->original_environment, &current_settings->current_environment, saved_envp);
  current_settings->current_environment = saved_envp;

  return(return_value);
  }

int config_test_configuration_dir_file(struct filter_settings *current_settings, struct spamdyke_option *target_option, char *target_filename)
  {
  int return_value;
  int tmp_log_level;

  return_value = 1;

  if (target_filename != NULL)
    {
    tmp_log_level = current_settings->current_options->log_level;

    if (copy_base_options(current_settings, FILTER_DECISION_UNDECIDED) != FILTER_DECISION_ERROR)
      {
      init_option_set(current_settings, current_settings->current_options);
      current_settings->current_options->log_level = tmp_log_level;
      current_settings->current_options->log_target = LOG_USE_CONFIG_TEST;

      if ((process_config_file(current_settings, target_filename, FILTER_DECISION_UNDECIDED, CONFIG_LOCATION_DIR, NULL) == FILTER_DECISION_ERROR) ||
          !config_test_options(current_settings))
        return_value = 0;

      free_current_options(current_settings, NULL);
      }
    }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_configuration_dir_structure(struct filter_settings *current_settings, struct spamdyke_option *target_option, char *target_dir, int depth, int most_recent, int most_recent_depth, int found_ip, int found_rdns, int found_recipient, int found_recipient_username, int found_sender, int found_sender_username)
  {
  int return_value;
  DIR *tmp_dir;
  struct dirent *tmp_ent;
  char tmp_name[MAX_BUF + 1];
  int new_recent;
  int new_recent_depth;
  int tmp_int;
  char *most_recent_name;

  return_value = 1;

  if (target_dir != NULL)
    {
    if ((tmp_dir = opendir(target_dir)) != NULL)
      {
      switch (most_recent)
        {
        case 1:
          most_recent_name = CONFIG_DIR_IP;
          break;
        case 2:
          most_recent_name = CONFIG_DIR_NAME;
          break;
        case 3:
          most_recent_name = CONFIG_DIR_RECIPIENT;
          break;
        case 5:
          most_recent_name = CONFIG_DIR_SENDER;
          break;
        case 4:
        case 6:
          most_recent_name = CONFIG_DIR_USERNAME;
          break;
        default:
          most_recent_name = NULL;
          break;
        }

      while ((tmp_ent = readdir(tmp_dir)) != NULL)
        if ((strcmp(tmp_ent->d_name, DIR_CURRENT) != 0) &&
            (strcmp(tmp_ent->d_name, DIR_PARENT) != 0))
          {
          snprintf(tmp_name, MAX_BUF, "%s" DIR_DELIMITER_STR "%s", target_dir, tmp_ent->d_name);

          switch (config_test_file_type(target_dir, tmp_ent))
            {
            case S_IFDIR:
              if (strcasecmp(CONFIG_DIR_IP, tmp_ent->d_name) == 0)
                {
                if (found_ip)
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_DUPLICATE_DIR, target_option->getopt_option.name, CONFIG_DIR_IP, tmp_name);
                if ((depth - most_recent_depth) == 1)
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_MISSING_DATA, target_option->getopt_option.name, CONFIG_DIR_IP, most_recent_name, tmp_name);

                if (!config_test_configuration_dir_structure(current_settings, target_option, tmp_name, depth + 1, 1, depth, 1, found_rdns, found_recipient, found_recipient_username, found_sender, found_sender_username))
                  return_value = 0;
                }
              else if (strcasecmp(CONFIG_DIR_NAME, tmp_ent->d_name) == 0)
                {
                if (found_rdns)
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_DUPLICATE_DIR, target_option->getopt_option.name, CONFIG_DIR_NAME, tmp_name);
                if ((depth - most_recent_depth) == 1)
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_MISSING_DATA, target_option->getopt_option.name, CONFIG_DIR_NAME, most_recent_name, tmp_name);

                if (!config_test_configuration_dir_structure(current_settings, target_option, tmp_name, depth + 1, 2, depth, found_ip, 1, found_recipient, found_recipient_username, found_sender, found_sender_username))
                  return_value = 0;
                }
              else if (strcasecmp(CONFIG_DIR_RECIPIENT, tmp_ent->d_name) == 0)
                {
                if (found_recipient)
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_DUPLICATE_DIR, target_option->getopt_option.name, CONFIG_DIR_RECIPIENT, tmp_name);
                if ((depth - most_recent_depth) == 1)
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_MISSING_DATA, target_option->getopt_option.name, CONFIG_DIR_RECIPIENT, most_recent_name, tmp_name);

                if (!config_test_configuration_dir_structure(current_settings, target_option, tmp_name, depth + 1, 3, depth, found_ip, found_rdns, 1, found_recipient_username, found_sender, found_sender_username))
                  return_value = 0;
                }
              else if (strcasecmp(CONFIG_DIR_SENDER, tmp_ent->d_name) == 0)
                {
                if (found_sender)
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_DUPLICATE_DIR, target_option->getopt_option.name, CONFIG_DIR_SENDER, tmp_name);
                if ((depth - most_recent_depth) == 1)
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_MISSING_DATA, target_option->getopt_option.name, CONFIG_DIR_SENDER, most_recent_name, tmp_name);

                if (!config_test_configuration_dir_structure(current_settings, target_option, tmp_name, depth + 1, 5, depth, found_ip, found_rdns, found_recipient, found_recipient_username, 1, found_sender_username))
                  return_value = 0;
                }
              else if (strcasecmp(CONFIG_DIR_USERNAME, tmp_ent->d_name) == 0)
                {
                new_recent = most_recent;
                new_recent_depth = most_recent_depth;

                if (most_recent == 3)
                  {
                  if (found_recipient_username)
                    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_DUPLICATE_USERNAME, target_option->getopt_option.name, CONFIG_DIR_USERNAME, CONFIG_DIR_RECIPIENT, tmp_name);

                  new_recent = 4;
                  new_recent_depth = depth;
                  }
                else if (most_recent == 5)
                  {
                  if (found_sender_username)
                    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_DUPLICATE_USERNAME, target_option->getopt_option.name, CONFIG_DIR_USERNAME, CONFIG_DIR_SENDER, tmp_name);

                  new_recent = 6;
                  new_recent_depth = depth;
                  }
                else
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_MISPLACED_USERNAME, target_option->getopt_option.name, CONFIG_DIR_USERNAME, CONFIG_DIR_RECIPIENT, CONFIG_DIR_SENDER, tmp_name);

                if ((depth - most_recent_depth) == 1)
                  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_MISSING_DATA, target_option->getopt_option.name, CONFIG_DIR_USERNAME, most_recent_name, tmp_name);

                if (!config_test_configuration_dir_structure(current_settings, target_option, tmp_name, depth + 1, new_recent, new_recent_depth, found_ip, found_rdns, found_recipient, (new_recent == 4) ? 1 : found_recipient_username, found_sender, (new_recent == 6) ? 1 : found_sender_username))
                  return_value = 0;
                }
              else
                {
                if (most_recent == 1)
                  {
                  if ((sscanf(tmp_ent->d_name, "%d", &tmp_int) != 1) ||
                      (tmp_int < 0) ||
                      (tmp_int > 255))
                    {
                    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_IP_BAD_OCTET, target_option->getopt_option.name, tmp_ent->d_name, CONFIG_DIR_IP, tmp_name);
                    return_value = 0;
                    }

                  if ((depth - most_recent_depth) > 4)
                    {
                    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_IP_TOO_DEEP, target_option->getopt_option.name, CONFIG_DIR_IP, tmp_name);
                    return_value = 0;
                    }
                  }
                else if ((most_recent == 4) ||
                         (most_recent == 6))
                  {
                  if ((depth - most_recent_depth) > 1)
                    {
                    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_USERNAME_TOO_DEEP, target_option->getopt_option.name, CONFIG_DIR_USERNAME, tmp_name);
                    return_value = 0;
                    }
                  }

                if (!config_test_configuration_dir_structure(current_settings, target_option, tmp_name, depth + 1, most_recent, most_recent_depth, found_ip, found_rdns, found_recipient, found_recipient_username, found_sender, found_sender_username))
                  return_value = 0;
                }

              break;
            case S_IFREG:
              if ((strcasecmp(CONFIG_DIR_IP, tmp_ent->d_name) == 0) ||
                  (strcasecmp(CONFIG_DIR_NAME, tmp_ent->d_name) == 0) ||
                  (strcasecmp(CONFIG_DIR_RECIPIENT, tmp_ent->d_name) == 0) ||
                  (strcasecmp(CONFIG_DIR_SENDER, tmp_ent->d_name) == 0) ||
                  (strcasecmp(CONFIG_DIR_USERNAME, tmp_ent->d_name) == 0))
                SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_BAD_FILENAME, target_option->getopt_option.name, tmp_ent->d_name, tmp_name);

              if (!config_test_configuration_dir_file(current_settings, target_option, tmp_name))
                return_value = 0;

              break;
            default:
              SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_BAD_TYPE, target_option->getopt_option.name, config_test_file_type_string(tmp_name, tmp_ent), tmp_name);
              return_value = 0;
              break;
            }
          }

      closedir(tmp_dir);
      }
    else
      SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_OPENDIR, target_option->getopt_option.name, target_dir, strerror(errno));
    }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_configuration_dir(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;
  int i;
  struct stat tmp_stat;

  return_value = 1;

  if (current_settings->current_options->configuration_dir != NULL)
    for (i = 0; current_settings->current_options->configuration_dir[i] != NULL; i++)
      {
      SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_START_CONFIGURATION_DIR, target_option->getopt_option.name, current_settings->current_options->configuration_dir[i]);

      if (stat(current_settings->current_options->configuration_dir[i], &tmp_stat) == 0)
        if (S_ISDIR(tmp_stat.st_mode))
          if (config_test_configuration_dir_structure(current_settings, target_option, current_settings->current_options->configuration_dir[i], 0, 0, 0, 0, 0, 0, 0, 0, 0))
            SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_SUCCESS_CONFIGURATION_DIR, target_option->getopt_option.name, current_settings->current_options->configuration_dir[i]);
          else
            return_value = 0;
        else
          {
          SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_ERROR_CONFIGURATION_DIR_TOP_OTHER, target_option->getopt_option.name, config_test_stat_type(tmp_stat.st_mode), current_settings->current_options->configuration_dir[i]);
          return_value = 0;
          }
      else
        {
        SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, LOG_ERROR_STAT "%s", current_settings->current_options->configuration_dir[i]);
        return_value = 0;
        }
      }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_cdb(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;
  int i;
  char ***string_array;

  return_value = 1;

  if (((string_array = (*(target_option->getter.get_string_array))(current_settings->current_options, 0)) != NULL) &&
      ((*string_array) != NULL))
    for (i = 0; (*string_array)[i] != NULL; i++)
      {
      SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_START_CDB, target_option->getopt_option.name, (*string_array)[i]);

      if ((target_option->default_value.string_value != NULL) &&
          ((i != 0) ||
           strcmp((*string_array)[i], target_option->default_value.string_value)))
        SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_QMAIL_NONDEFAULT, target_option->getopt_option.name, target_option->default_value.string_value);

      if (validate_cdb(current_settings, (*string_array)[i], (char *)target_option->getopt_option.name))
        SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_SUCCESS_CDB, target_option->getopt_option.name, (*string_array)[i]);
      else
        {
        SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_FAILURE_CDB, target_option->getopt_option.name, (*string_array)[i]);
        return_value = 0;
        }
      }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_qmail_option(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  int return_value;
  int i;
  int test_result;
  char ***string_array;
  char **string_value;

  return_value = 1;

  if (target_option->value_type == CONFIG_TYPE_FILE_SINGLETON)
    {
    if (((string_value = (*(target_option->getter.get_string))(current_settings->current_options, 0)) != NULL) &&
        ((*string_value) != NULL) &&
        (target_option->default_value.string_value != NULL))
      {
      if (strcmp((*string_value), target_option->default_value.string_value))
        SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_QMAIL_NONDEFAULT, target_option->getopt_option.name, target_option->default_value.string_value);

      test_result = config_test_file_read(current_settings, (*string_value), (char *)target_option->getopt_option.name, NULL, CONFIG_TEST_SUCCESS_FILE_READ, CONFIG_TEST_ERROR_FILE_READ, NULL, 0, NULL);
      if (return_value)
        return_value = test_result;
      }
    }
  else if (target_option->value_type == CONFIG_TYPE_FILE_ARRAY)
    {
    if (((string_array = (*(target_option->getter.get_string_array))(current_settings->current_options, 0)) != NULL) &&
        ((*string_array) != NULL) &&
        (target_option->default_value.string_value != NULL))
      {
      for (i = 0; (*string_array)[i] != NULL; i++)
        {
        if ((i != 0) ||
            strcmp((*string_array)[i], target_option->default_value.string_value))
          SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(current_settings, CONFIG_TEST_QMAIL_NONDEFAULT, target_option->getopt_option.name, target_option->default_value.string_value);

        test_result = config_test_file_read(current_settings, (*string_array)[i], (char *)target_option->getopt_option.name, NULL, CONFIG_TEST_SUCCESS_FILE_READ, CONFIG_TEST_ERROR_FILE_READ, NULL, 0, NULL);
        if (return_value)
          return_value = test_result;
        }
      }
    }
  else
    {
    SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, LOG_ERROR_OPTION_LIST_TYPE, target_option->getopt_option.name);
    return_value = 0;
    }

  return(return_value);
  }

#else /* WITHOUT_CONFIG_TEST */

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_graylist(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_rdns_dir(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_smtpauth(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_tls_certificate(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_tls_privatekey(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_tls_password(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_relay_level(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_configuration_dir(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_cdb(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_qmail_option(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_noop(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test_tls_dhparams(struct filter_settings *current_settings, struct spamdyke_option *target_option)
  {
  return(0);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int config_test(struct filter_settings *current_settings, int argc, char *argv[])
  {
  usage(current_settings, USAGE_LEVEL_SHORT, NULL);

  current_settings->current_options->log_level = MAXVAL(LOG_LEVEL_ERROR, current_settings->current_options->log_level);
  current_settings->current_options->log_target = LOG_USE_CONFIG_TEST;
  SPAMDYKE_LOG_CONFIG_TEST_ERROR(current_settings, CONFIG_TEST_MISSING);

  return(0);
  }

#endif /* WITHOUT_CONFIG_TEST */
