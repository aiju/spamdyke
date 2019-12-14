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
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <pwd.h>
#include <errno.h>
#include "spamdyke-qrv.h"
#include "validate-qrv.h"
#include "log-qrv.h"
#include "fs-qrv.h"
#include "cdb-qrv.h"
#include "exec-qrv.h"

/*
 * new_address must be NULL-terminated.
 *
 * RETURN:
 *   0: no match
 *   1: match
 */
int compare_addresses(struct qrv_settings *current_settings, char *new_address, char *old_username, int strlen_old_username, char *old_domain, int strlen_old_domain)
  {
  int return_value;
  int i;
  int strlen_new_username;
  int strlen_new_domain;

  return_value = 0;

  if (new_address != NULL)
    {
    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_RECIPIENT_COMPARE, new_address, old_username, (strlen_old_domain > 0) ? "@" : "", old_domain);

    /* FIXME: Should this use find_address() instead? */
    strlen_new_username = -1;
    strlen_new_domain = -1;
    for (i = 0; new_address[i] != '\0'; i++)
      if (new_address[i] == '@')
        strlen_new_username = i;
    if (strlen_new_username == -1)
      {
      strlen_new_username = i;
      strlen_new_domain = 0;
      }
    else
      strlen_new_domain = (i - strlen_new_username) - 1;

    if ((strlen_new_username == strlen_old_username) &&
        (strlen_new_domain == strlen_new_domain) &&
        !strncmp(new_address, old_username, strlen_old_username) &&
        ((strlen_old_domain == 0) ||
         !strncmp(new_address + strlen_new_username + 1, old_domain, strlen_old_domain)))
      return_value = 1;
    }

  return(return_value);
  }

/*
 * RETURN:
 *   DECISION_ERROR: error occurred
 *   DECISION_UNKNOWN: no decision reached -- is this an error?
 *   DECISION_VALID: address is valid
 *   DECISION_INVALID: address is invalid
 *   DECISION_UNAVAILABLE: address is "unavailable"
 */
int validate(struct qrv_settings *current_settings, char *target_recipient_username, int strlen_recipient_username, char *target_recipient_domain, struct validate_history *last)
  {
  int return_value;
  int i;
  int j;
  int k;
  int continue_processing;
  int current_step;
  char working_username[MAX_ADDRESS + 1];
  int strlen_working_username;
  char working_domain[MAX_ADDRESS + 1];
  int strlen_working_domain;
  char forward_domain[MAX_ADDRESS + 1];
  int strlen_forward_domain;
  int found_match;
  int tmp_loc;
  int num_loop;
  char tmp_line[MAX_FILE_BUF + 1];
  int tmp_strlen;
  char qmail_prefix[MAX_PATH + 1];
  int strlen_qmail_prefix;
  char qmail_home[MAX_PATH + 1];
  char qmail_dash[MAX_PATH + 1];
  char qmail_ext[MAX_PATH + 1];
  int strlen_qmail_ext;
  char tmp_filename[MAX_PATH + 1];
  char tmp_name[MAX_ADDRESS + 1];
  int strlen_tmp_name;
  char tmp_path[MAX_PATH + 1];
  char tmp_unreal_path[MAX_PATH + 1];
  struct stat tmp_stat;
  int tmp_return;
  int max_line;
  struct passwd *tmp_passwd;
  int forward_only;
  char tmp_qmail_filename[MAX_PATH + 1];
  char tmp_qmail_path[MAX_PATH + 1];
  char **qmail_lines;
  int current_line;
  int num_lines;
  int last_line;
  int total_lines;
  char *tmp_file_line;
  int strlen_found_key;
  char tmp_address[MAX_ADDRESS + 1];
  int tmp_uid;
  int tmp_gid;
  int strlen_recipient_domain;
  struct validate_history current;
  struct validate_history *tmp_history;
  int forward_depth;
  int tmp_strlen_command;
  int tmp_last_parameter;
  int assign_wildcard_domain_hyphen;
  int virtualdomains_domain_only;
  int percent_in_username;

#ifdef WITH_VPOPMAIL_SUPPORT

  char *tmp_argv[4];
  char vpopmail_output[MAX_BUF + 1];
  char *vpopmail_output_ptr;
  int tmp_strlen_output;
  int tmp_status;
  char vpopmail_username[MAX_ADDRESS + 1];
  int strlen_vpopmail_username;
  char vpopmail_domain[MAX_ADDRESS + 1];
  int strlen_vpopmail_domain;

#endif /* WITH_VPOPMAIL_SUPPORT */

#ifdef WITH_EXCESSIVE_OUTPUT

  char decision_path[MAX_BUF + 1];
  int strlen_decision_path;
  int new_strlen;

  decision_path[0] = '\0';
  strlen_decision_path = 0;

#endif /* WITH_EXCESSIVE_OUTPUT */

  return_value = DECISION_UNKNOWN;
  continue_processing = 1;
  num_loop = 0;
  i = 0;
  current_line = 0;
  tmp_last_parameter = 0;

#ifdef WITH_VPOPMAIL_SUPPORT

  vpopmail_username[0] = '\0';
  strlen_vpopmail_username = 0;
  vpopmail_domain[0] = '\0';
  strlen_vpopmail_domain = 0;
  vpopmail_output_ptr = NULL;
  tmp_strlen_output = 0;

#endif /* WITH_VPOPMAIL_SUPPORT */

  forward_depth = 0;
  tmp_history = last;
  while (tmp_history != NULL)
    {
    if ((tmp_history->strlen_username == strlen_recipient_username) &&
        !strncmp(tmp_history->username, target_recipient_username, strlen_recipient_username) &&
        !strcmp(tmp_history->domain, target_recipient_domain))
      {
      QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_LOOP, strlen_recipient_username, target_recipient_username, target_recipient_domain);
      return_value = DECISION_INVALID;
      break;
      }

    forward_depth++;
    tmp_history = tmp_history->previous;
    }

  if (return_value == DECISION_UNKNOWN)
    {
    current.username = target_recipient_username;
    current.strlen_username = strlen_recipient_username;
    current.domain = target_recipient_domain;
    current.previous = last;

    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_START, strlen_recipient_username, target_recipient_username, target_recipient_domain);
    strlen_working_username = SNPRINTF(working_username, MAX_ADDRESS, "%.*s", strlen_recipient_username, target_recipient_username);
    strlen_working_domain = SNPRINTF(working_domain, MAX_ADDRESS, "%s", target_recipient_domain);
    strlen_recipient_domain = strlen_working_domain;

    forward_domain[0] = '\0';
    strlen_forward_domain = 0;

#ifndef WITH_VPOPMAIL_SUPPORT

    /*
     * This is stupid, but it defeats a variable-assigned-but-never-used warning
     * from gcc when vpopmail support is not available.
     */
    i = strlen_recipient_domain;

#endif /* WITH_VPOPMAIL_SUPPORT */

    if (last != NULL)
      current_step = 2;
    else
      {
      current_step = 7;

      if ((current_settings->relayclient != NULL) &&
          (current_settings->relayclient[0] != '\0'))
        {
        if (current_settings->recipient_domain[0] != '\0')
          strlen_working_domain = SNPRINTF(working_domain, MAX_ADDRESS, "%s%s", target_recipient_domain, current_settings->relayclient);
        else
          strlen_working_username = SNPRINTF(working_username, MAX_ADDRESS, "%s%s", target_recipient_username, current_settings->relayclient);
        }
      }

    tmp_loc = 0;
    max_line = -1;
    forward_only = 0;
    tmp_line[0] = '\0';
    tmp_strlen = 0;
    qmail_prefix[0] = '\0';
    strlen_qmail_prefix = 0;
    qmail_home[0] = '\0';
    qmail_dash[0] = '\0';
    qmail_ext[0] = '\0';
    strlen_qmail_ext = 0;
    tmp_filename[0] = '\0';
    tmp_name[0] = '\0';
    strlen_tmp_name = 0;
    last_line = 0;
    qmail_lines = NULL;
    tmp_file_line = NULL;
    total_lines = 0;
    num_lines = 0;
    strlen_found_key = 0;
    tmp_uid = -1;
    tmp_gid = -1;
    tmp_path[0] = '\0';
    assign_wildcard_domain_hyphen = 0;
    virtualdomains_domain_only = 0;
    percent_in_username = 0;

    /*
     * This process is implemented as a switch statement because doing it all with
     * if/else statements was just too hairy and goto is considered harmful, right?
     * As a former coworker would say, this is a deterministic finite state automaton.
     * (He said it a lot to try to sound smart.)
     *
     * This doesn't seem to make a lot of sense by itself, but it all becomes much
     * clearer when compared to the recipient validation flowchart.  The step
     * numbers correspond to the labels in the flowchart.
     */
    if (forward_depth < MAX_VALIDATE_DEPTH)
      {
      while (continue_processing)
        {
        QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_STEP, current_step, strlen_working_username, working_username, working_domain, tmp_name, tmp_filename, tmp_path, qmail_dash, qmail_ext);

#ifdef WITH_EXCESSIVE_OUTPUT

        new_strlen = SNPRINTF(decision_path + strlen_decision_path, MAX_BUF - strlen_decision_path, "%.2d_", current_step);
        strlen_decision_path += new_strlen;

#endif /* WITH_EXCESSIVE_OUTPUT */

        num_loop++;
        if (num_loop > 1000)
          {
          QRV_LOG_ERROR(current_settings, LOG_ERROR_VALIDATE_LOOP, NULL);
          break;
          }

        switch (current_step)
          {
          case 2:
            if (last != NULL)
              current_step = (strlen_working_domain > 0) ? 12 : 3;
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 3:
            if (current_settings->qmail_envnoathost_file != NULL)
              if ((tmp_return = check_path_perms(current_settings, current_settings->qmail_envnoathost_file, S_IFREG, FILE_PERMISSION_READ, NULL, -1, -1)) == 1)
                {
                if ((tmp_strlen = read_file_first_line(current_settings, current_settings->qmail_envnoathost_file, &tmp_file_line)) > 0)
                  {
                  strlen_working_domain = MINVAL(MAX_ADDRESS, tmp_strlen);
                  memcpy(working_domain, tmp_file_line, strlen_working_domain);
                  working_domain[strlen_working_domain] = '\0';

                  current_step = 7;
                  }
                else if (tmp_strlen == 0)
                  current_step = 4;
                else
                  {
                  return_value = DECISION_ERROR;
                  continue_processing = 0;
                  }

                if (tmp_file_line != NULL)
                  {
                  free(tmp_file_line);
                  tmp_file_line = NULL;
                  }
                }
              else if (tmp_return == 0)
                current_step = 4;
              else
                {
                return_value = DECISION_ERROR;
                continue_processing = 0;
                }
            else
              current_step = 4;

            break;
          case 4:
            if (current_settings->qmail_me_file != NULL)
              if ((tmp_return = check_path_perms(current_settings, current_settings->qmail_me_file, S_IFREG, FILE_PERMISSION_READ, NULL, -1, -1)) == 1)
                {
                if ((tmp_strlen = read_file_first_line(current_settings, current_settings->qmail_me_file, &tmp_file_line)) > 0)
                  {
                  strlen_working_domain = MINVAL(MAX_ADDRESS, tmp_strlen);
                  memcpy(working_domain, tmp_file_line, strlen_working_domain);
                  working_domain[strlen_working_domain] = '\0';

                  current_step = 7;
                  }
                else if (tmp_strlen == 0)
                  {
                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
                  return_value = DECISION_INVALID;
                  continue_processing = 0;
                  }
                else
                  {
                  return_value = DECISION_ERROR;
                  continue_processing = 0;
                  }

                if (tmp_file_line != NULL)
                  {
                  free(tmp_file_line);
                  tmp_file_line = NULL;
                  }
                }
              else if (tmp_return == 0)
                {
                QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
                return_value = DECISION_INVALID;
                continue_processing = 0;
                }
              else
                {
                return_value = DECISION_ERROR;
                continue_processing = 0;
                }
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }

            break;
          case 7:
            found_match = 0;
            for (tmp_loc = (strlen_working_username - 1); tmp_loc >= 0; tmp_loc--)
              if (working_username[tmp_loc] == QMAIL_PERCENTHACK_TARGET)
                {
                QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_PERCENT_FOUND, working_username);
                found_match = 1;
                break;
                }

            current_step = (found_match) ? 8 : 9;
            break;
          case 8:
            found_match = 0;
            if ((tmp_loc >= 0) &&
                (tmp_loc < strlen_working_username) &&
                (current_settings->qmail_percenthack_file != NULL))
              for (i = 0; current_settings->qmail_percenthack_file[i] != NULL; i++)
                {
                if ((tmp_return = search_file(current_settings, current_settings->qmail_percenthack_file[i], working_domain, strlen_working_domain, '\0', NULL, '\0', NULL)) > 0)
                  {
                  strlen_working_domain = (strlen_working_username - tmp_loc) - 1;
                  memcpy(working_domain, working_username + tmp_loc + 1, strlen_working_domain);
                  working_domain[strlen_working_domain] = '\0';

                  working_username[tmp_loc] = '\0';
                  strlen_working_username = tmp_loc;

                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_PERCENTHACK_FOUND, current_settings->qmail_percenthack_file[i], working_username, working_domain);
                  found_match = 1;
                  break;
                  }
                else if (tmp_return == -1)
                  {
                  continue_processing = 0;
                  break;
                  }
                }

            percent_in_username = (found_match) ? 0 : 1;
            current_step = (found_match) ? 7 : 9;
            break;
          case 9:
            found_match = 0;
            if (current_settings->qmail_locals_file != NULL)
              for (i = 0; current_settings->qmail_locals_file[i] != NULL; i++)
                {
                if ((tmp_return = search_file(current_settings, current_settings->qmail_locals_file[i], working_domain, strlen_working_domain, '\0', NULL, '\0', NULL)) > 0)
                  {
                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_LOCALS_FILE, current_settings->qmail_locals_file[i], working_domain);
                  found_match = 1;
                  break;
                  }
                else if (tmp_return == -1)
                  {
                  continue_processing = 0;
                  break;
                  }
                }

            current_step = (found_match) ? 12 : 10;
            break;
          case 10:
            found_match = 0;
            if (current_settings->qmail_virtualdomains_file != NULL)
              for (i = 0; current_settings->qmail_virtualdomains_file[i] != NULL; i++)
                {
                tmp_strlen = MAX_FILE_BUF;
                if ((tmp_return = search_virtualdomains_file(current_settings, current_settings->qmail_virtualdomains_file[i], working_domain, strlen_working_domain, tmp_line, &tmp_strlen)) > 0)
                  {
                  memcpy(tmp_address, working_username, strlen_working_username);
                  tmp_address[strlen_working_username] = '\0';
                  strlen_working_username = SNPRINTF(working_username, MAX_ADDRESS, "%s-%s", tmp_line, tmp_address);

                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_VIRTUALDOMAIN, working_domain, current_settings->qmail_virtualdomains_file[i], tmp_line, working_username);
                  found_match = 1;
                  break;
                  }
                else if (tmp_return == -1)
                  {
                  continue_processing = 0;
                  break;
                  }
                else
                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_VIRTUALDOMAIN_NONE, working_domain, current_settings->qmail_virtualdomains_file[i]);
                }

            if (found_match)
              current_step = 11;
            else
              continue_processing = 0;

            break;
          case 11:
            QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VPOPMAIL_VIRTUALDOMAINS, strlen_working_domain, working_domain, tmp_line);
            tmp_strlen = strlen(tmp_line);
            if ((tmp_strlen == strlen_working_domain) &&
                !strncmp(tmp_line, working_domain, strlen_working_domain))
              virtualdomains_domain_only = 1;

            current_step = 12;

            break;
          case 12:
            found_match = 0;
            tmp_line[0] = '\0';
            tmp_strlen = 0;
            if (current_settings->qmail_assign_cdb != NULL)
              for (i = 0; current_settings->qmail_assign_cdb[i] != NULL; i++)
                if ((tmp_strlen = search_assign_cdb(current_settings, tmp_line, MAX_FILE_BUF, current_settings->qmail_assign_cdb[i], working_username, strlen_working_username, &strlen_found_key)) > 0)
                  {
                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_ASSIGN, working_username, current_settings->qmail_assign_cdb[i], tmp_line);
                  found_match = 1;
                  break;
                  }

            if (found_match)
              {
              j = 0;
              k = 0;
              qmail_home[0] = '\0';
              qmail_dash[0] = '\0';
              qmail_ext[0] = '\0';
              strlen_qmail_ext = 0;

              strlen_qmail_prefix = (strlen_found_key >= 0) ? MINVAL(MAX_PATH, strlen_found_key) : MINVAL(MAX_PATH, strlen_working_username);
              memcpy(qmail_prefix, working_username, strlen_qmail_prefix);
              qmail_prefix[strlen_qmail_prefix] = '\0';

              for (i = 1; i < tmp_strlen; i++)
                if (tmp_line[i] == QMAIL_ASSIGN_DELIMITER)
                  {
                  j++;
                  k = 0;
                  }
                else if (j == 1)
                  {
                  if ((i > 0) &&
                      (tmp_line[i - 1] == QMAIL_ASSIGN_DELIMITER) &&
                      ((sscanf(tmp_line + i, "%d", &tmp_uid) != 1) ||
                       (tmp_uid < 0)))
                    tmp_uid = -1;
                  }
                else if (j == 2)
                  {
                  if ((i > 0) &&
                      (tmp_line[i - 1] == QMAIL_ASSIGN_DELIMITER) &&
                      ((sscanf(tmp_line + i, "%d", &tmp_gid) != 1) ||
                       (tmp_gid < 0)))
                    tmp_gid = -1;
                  }
                else if (j == 3)
                  {
                  if (k < MAX_PATH)
                    {
                    qmail_home[k++] = tmp_line[i];
                    qmail_home[k] = '\0';
                    }
                  }
                else if (j == 4)
                  {
                  if (k < MAX_PATH)
                    {
                    qmail_dash[k++] = tmp_line[i];
                    qmail_dash[k] = '\0';
                    }
                  }
                else if (j == 5)
                  {
                  if (strlen_qmail_ext < MAX_PATH)
                    {
                    qmail_ext[strlen_qmail_ext++] = (tmp_line[i] == QMAIL_REPLACE_EXT_TARGET) ? QMAIL_REPLACE_EXT_REPLACEMENT : tolower((int)tmp_line[i]);
                    qmail_ext[strlen_qmail_ext] = '\0';
                    }
                  }

              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_ASSIGN_VALUES, qmail_prefix, qmail_home, qmail_dash, qmail_ext);

              if (strlen_found_key == -1)
                {

#ifdef WITH_VPOPMAIL_SUPPORT

                strlen_vpopmail_username = SNPRINTF(vpopmail_username, MAX_ADDRESS, "%s", qmail_ext);
                vpopmail_username[strlen_vpopmail_username] = '\0';
                strlen_vpopmail_domain = MINVAL(MAX_ADDRESS, strlen_working_domain);
                memcpy(vpopmail_domain, working_domain, strlen_working_domain);
                vpopmail_domain[strlen_vpopmail_domain] = '\0';

                for (i = 0; i < strlen_vpopmail_username; i++)
                  if (vpopmail_username[i] == QMAIL_REPLACE_EXT_REPLACEMENT)
                    vpopmail_username[i] = QMAIL_REPLACE_EXT_TARGET;

#endif /* WITH_VPOPMAIL_SUPPORT */

                snprintf(tmp_filename, MAX_PATH, ".qmail%s%s", qmail_dash, qmail_ext);
                current_step = 15;
                }
              else
                current_step = 13;
              }
            else
              current_step = 13;

            break;
          case 13:
            if ((tmp_strlen > 0) &&
                (strlen_found_key >= 0))
              {
              for (i = strlen_qmail_prefix; (i < strlen_working_username) && (strlen_qmail_ext < MAX_PATH); i++)
                {
                qmail_ext[strlen_qmail_ext] = (working_username[i] == QMAIL_REPLACE_EXT_TARGET) ? QMAIL_REPLACE_EXT_REPLACEMENT : tolower((int)working_username[i]);
                strlen_qmail_ext++;
                }
              qmail_ext[strlen_qmail_ext] = '\0';

              snprintf(tmp_filename, MAX_PATH, ".qmail%s%s", qmail_dash, qmail_ext);

              current_step = 14;
              }
            else
              {
              strlen_tmp_name = strlen_working_username;
              memcpy(tmp_name, working_username, strlen_working_username);
              tmp_name[strlen_tmp_name] = '\0';

              current_step = 30;
              }

            break;
          case 14:

#ifdef WITH_VPOPMAIL_SUPPORT

            strlen_vpopmail_username = SNPRINTF(vpopmail_username, MAX_ADDRESS, "%s", qmail_ext);
            vpopmail_username[strlen_vpopmail_username] = '\0';
            strlen_vpopmail_domain = MINVAL(MAX_ADDRESS, strlen_working_domain);
            memcpy(vpopmail_domain, working_domain, strlen_working_domain);
            vpopmail_domain[strlen_vpopmail_domain] = '\0';

            for (i = 0; i < strlen_vpopmail_username; i++)
              if (vpopmail_username[i] == QMAIL_REPLACE_EXT_REPLACEMENT)
                vpopmail_username[i] = QMAIL_REPLACE_EXT_TARGET;

#endif /* WITH_VPOPMAIL_SUPPORT */

            QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VPOPMAIL_ASSIGN, strlen_qmail_prefix, qmail_prefix, strlen_working_domain, working_domain);
            if (((strlen_working_domain + 1) == strlen_qmail_prefix) &&
                (qmail_prefix[strlen_working_domain] == '-') &&
                !strncmp(qmail_prefix, working_domain, strlen_working_domain))
              assign_wildcard_domain_hyphen = 1;

            current_step = 22;
            break;
          case 15:
          case 22:
            if ((tmp_return = check_path_perms(current_settings, qmail_home, S_IFDIR, 0, &tmp_stat, tmp_uid, tmp_gid)) == 1)
              current_step = (current_step == 15) ? 16 : 23;
            else if (tmp_return == 0)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 16:
          case 23:
            if ((tmp_return = check_path_perms(current_settings, qmail_home, S_IFDIR, FILE_PERMISSION_READ | FILE_PERMISSION_EXECUTE, &tmp_stat, tmp_uid, tmp_gid)) == 1)
              current_step = (current_step == 16) ? 17 : 24;
            else if (tmp_return == 0)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 17:
          case 24:
            if ((tmp_stat.st_mode & S_IWOTH) == 0)
              current_step = (current_step == 17) ? 18 : 25;
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_HOME_WRITEABLE, qmail_home);
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }

            break;
          case 18:
          case 25:
            if ((tmp_return = check_path_perms(current_settings, qmail_home, S_IFDIR, FILE_PERMISSION_STICKY | FILE_PERMISSION_EXECUTE, &tmp_stat, tmp_uid, tmp_gid)) == 0)
              current_step = (current_step == 18) ? 19 : 26;
            else if (tmp_return == 1)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 19:
            snprintf(tmp_path, MAX_PATH, "%s/%s", qmail_home, tmp_filename);
            if ((tmp_return = check_path_perms(current_settings, tmp_path, S_IFREG, 0, &tmp_stat, tmp_uid, tmp_gid)) == 1)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_FILE_EXISTS, tmp_path);
              current_step = 34;
              }
            else if (tmp_return == 0)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_FILE_DOES_NOT_EXIST, tmp_path);
              snprintf(tmp_filename, MAX_PATH, ".qmail%sdefault", qmail_dash);
              current_step = 20;
              }
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 20:
          case 26:
            snprintf(tmp_path, MAX_PATH, "%s/%s", qmail_home, tmp_filename);
            if ((tmp_return = check_path_perms(current_settings, tmp_path, S_IFREG, 0, &tmp_stat, tmp_uid, tmp_gid)) == 1)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_FILE_EXISTS, tmp_path);
              current_step = 34;
              }
            else if (tmp_return == 0)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_FILE_DOES_NOT_EXIST, tmp_path);
              current_step = (current_step == 20) ? 21 : 27;
              }
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 21:
            if ((qmail_dash[0] == '\0') &&
                (current_settings->qmail_defaultdelivery_file != NULL))
              {
              snprintf(tmp_path, MAX_PATH, "%s", current_settings->qmail_defaultdelivery_file);
              max_line = 1;
              current_step = 39;
              }
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_NO_DEFAULTDELIVERY, tmp_path);
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }

            break;
          case 27:
            found_match = 0;
            for (i = strlen_qmail_ext - 1; i >= 0; i--)
              if (qmail_ext[i] == QMAIL_EXT_TRUNCATE_TARGET)
                {
                found_match = 1;
                break;
                }

            if (found_match)
              {
              strlen_qmail_ext = i;
              qmail_ext[i] = '\0';
              snprintf(tmp_filename, MAX_PATH, ".qmail%s%s-default", qmail_dash, qmail_ext);
              current_step = 26;
              }
            else
              current_step = 28;

            break;
          case 28:
            if (strlen_qmail_ext == 0)
              current_step = 29;
            else
              {
              strlen_qmail_ext = 0;
              qmail_ext[0] = '\0';
              snprintf(tmp_filename, MAX_PATH, ".qmail%sdefault", qmail_dash);
              current_step = 26;
              }

            break;
          case 29:
            if ((qmail_dash[0] == '\0') &&
                (current_settings->qmail_defaultdelivery_file != NULL))
              {
              snprintf(tmp_path, MAX_PATH, "%s", current_settings->qmail_defaultdelivery_file);
              max_line = 1;
              current_step = 39;
              }
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_NO_DEFAULTDELIVERY, tmp_path);
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }

            break;
          case 30:
            if (strlen_tmp_name > 33)
              {
              strlen_tmp_name = 36;
              tmp_name[strlen_tmp_name] = '\0';
              current_step = 32;
              }
            else
              current_step = 31;

            break;
          case 31:
            found_match = 0;
            errno = 0;
            if ((tmp_passwd = getpwnam(tmp_name)) != NULL)
              {
              tmp_uid = tmp_passwd->pw_uid;
              tmp_gid = tmp_passwd->pw_gid;

              if (!stat(tmp_passwd->pw_dir, &tmp_stat))
                {
                if (tmp_stat.st_uid == tmp_passwd->pw_uid)
                  {
                  snprintf(qmail_home, MAX_PATH, "%s", tmp_passwd->pw_dir);

                  if (strlen_tmp_name == strlen_working_username)
                    qmail_dash[0] = '\0';
                  else
                    {
                    memcpy(qmail_dash, QMAIL_DASH_USER_FOUND, STRLEN(QMAIL_DASH_USER_FOUND));
                    qmail_dash[STRLEN(QMAIL_DASH_USER_FOUND)] = '\0';
                    }

                  strlen_qmail_ext = 0;
                  for (i = strlen_tmp_name + 1; i < strlen_working_username; i++)
                    {
                    qmail_ext[strlen_qmail_ext] = (working_username[i] == QMAIL_REPLACE_EXT_TARGET) ? QMAIL_REPLACE_EXT_REPLACEMENT : tolower((int)working_username[i]);
                    strlen_qmail_ext++;
                    }
                  qmail_ext[strlen_qmail_ext] = '\0';

                  snprintf(tmp_filename, MAX_PATH, ".qmail%s%s", qmail_dash, qmail_ext);

#ifdef WITH_VPOPMAIL_SUPPORT

                  strlen_vpopmail_username = SNPRINTF(vpopmail_username, MAX_ADDRESS, "%s%s", qmail_ext, target_recipient_username);
                  vpopmail_username[strlen_vpopmail_username] = '\0';
                  strlen_vpopmail_domain = MINVAL(MAX_ADDRESS, strlen_working_domain);
                  memcpy(vpopmail_domain, working_domain, strlen_working_domain);
                  vpopmail_domain[strlen_vpopmail_domain] = '\0';

                  for (i = 0; i < strlen_vpopmail_username; i++)
                    if (vpopmail_username[i] == QMAIL_REPLACE_EXT_REPLACEMENT)
                      vpopmail_username[i] = QMAIL_REPLACE_EXT_TARGET;

#endif /* WITH_VPOPMAIL_SUPPORT */

                  current_step = 26;
                  found_match = 1;
                  }
                else
                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_HOME_NOT_OWNED, tmp_passwd->pw_dir, tmp_name, tmp_passwd->pw_uid, tmp_stat.st_uid);
                }
              else
                QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_HOME_NOT_FOUND, tmp_passwd->pw_dir);
              }
            else if (errno != 0)
              {
              QRV_LOG_ERROR(current_settings, LOG_ERROR_GETUSER_ERRNO, tmp_name, strerror(errno));
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }
            else
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_USER_NOT_FOUND, tmp_name);

            if (!found_match)
              current_step = 32;

            break;
          case 32:
            found_match = 0;
            for (i = strlen_tmp_name - 1; i >= 0; i--)
              if (tmp_name[i] == QMAIL_USER_TRUNCATE_TARGET)
                {
                strlen_tmp_name = i;
                tmp_name[strlen_tmp_name] = '\0';
                found_match = 1;
                break;
                }

            current_step = (found_match) ? 31 : 33;
            break;
          case 33:
            errno = 0;
            if ((tmp_passwd = getpwnam(QMAIL_USER_ALIAS)) != NULL)
              {
              tmp_uid = tmp_passwd->pw_uid;
              tmp_gid = tmp_passwd->pw_gid;

              snprintf(qmail_home, MAX_PATH, "%s", tmp_passwd->pw_dir);

              memcpy(qmail_dash, QMAIL_DASH_USER_FOUND, STRLEN(QMAIL_DASH_USER_FOUND));
              qmail_dash[STRLEN(QMAIL_DASH_USER_FOUND)] = '\0';

              for (i = 0; i < strlen_working_username; i++)
                qmail_ext[i] = (working_username[i] == QMAIL_REPLACE_EXT_TARGET) ? QMAIL_REPLACE_EXT_REPLACEMENT : tolower((int)working_username[i]);
              strlen_qmail_ext = strlen_working_username;
              qmail_ext[strlen_qmail_ext] = '\0';

              snprintf(tmp_filename, MAX_PATH, ".qmail%s%s", qmail_dash, qmail_ext);

#ifdef WITH_VPOPMAIL_SUPPORT

              strlen_vpopmail_username = SNPRINTF(vpopmail_username, MAX_ADDRESS, "%s%s", qmail_ext, target_recipient_username);
              vpopmail_username[strlen_vpopmail_username] = '\0';
              strlen_vpopmail_domain = MINVAL(MAX_ADDRESS, strlen_working_domain);
              memcpy(vpopmail_domain, working_domain, strlen_working_domain);
              vpopmail_domain[strlen_vpopmail_domain] = '\0';

              for (i = 0; i < strlen_vpopmail_username; i++)
                if (vpopmail_username[i] == QMAIL_REPLACE_EXT_REPLACEMENT)
                  vpopmail_username[i] = QMAIL_REPLACE_EXT_TARGET;

#endif /* WITH_VPOPMAIL_SUPPORT */

              current_step = 26;
              }
            else if (errno != 0)
              {
              QRV_LOG_ERROR(current_settings, LOG_ERROR_GETUSER_ERRNO, QMAIL_USER_ALIAS, strerror(errno));
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_USER_NOT_FOUND, QMAIL_USER_ALIAS);
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }

            break;
          case 34:
            if ((tmp_return = check_path_perms(current_settings, tmp_path, S_IFREG, FILE_PERMISSION_READ, &tmp_stat, tmp_uid, tmp_gid)) == 1)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_FILE_READABLE, tmp_uid, tmp_gid, tmp_path);
              current_step = 35;
              }
            else if (tmp_return == 0)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_FILE_UNREADABLE, tmp_uid, tmp_gid, tmp_path);
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 35:
            if ((tmp_stat.st_mode & S_IWOTH) == 0)
              current_step = 36;
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_FILE_WRITEABLE, tmp_path);
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }

            break;
          case 36:
            if (tmp_stat.st_size > 0)
              current_step = 37;
            else if (current_settings->qmail_defaultdelivery_file != NULL)
              {
              snprintf(tmp_path, MAX_PATH, "%s", current_settings->qmail_defaultdelivery_file);
              max_line = 1;
              current_step = 39;
              }
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_NO_DEFAULTDELIVERY, tmp_path);
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }

            break;
          case 37:
            if (tmp_stat.st_mode & S_IXUSR)
              forward_only = 1;

            current_step = 38;
            break;
          case 38:
            if (qmail_lines == NULL)
              {
              if ((qmail_lines = (char **)malloc(sizeof(char *) * QMAIL_LINES_PER_READ)) != NULL)
                for (i = 0; i < QMAIL_LINES_PER_READ; i++)
                  qmail_lines[i] = NULL;
              else
                {
                QRV_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char *) * QMAIL_LINES_PER_READ);
                return_value = DECISION_ERROR;
                continue_processing = 0;
                break;
                }
              }
                
            found_match = 0;
            if (((num_lines = read_file(current_settings, tmp_path, &qmail_lines, 0, 1, QMAIL_LINES_PER_READ, 1)) > 1) &&
                (qmail_lines[0] != NULL))
              {
              for (i = 0; qmail_lines[0][i] != '\0'; i++)
                if (!isspace((int)qmail_lines[0][i]))
                  {
                  num_lines--;
                  found_match = 1;
                  break;
                  }
              }

            if (found_match)
              {
              current_line = 0;
              last_line = num_lines;
              current_step = 39;
              }
            else if (num_lines == -1)
              {
              QRV_LOG_VERBOSE(current_settings, LOG_VERBOSE_RECIPIENT_PERMISSION, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), tmp_path);
              continue_processing = 0;
              }
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }

            break;
          case 39:
            if (qmail_lines == NULL)
              {
              if ((qmail_lines = (char **)malloc(sizeof(char *) * QMAIL_LINES_PER_READ)) != NULL)
                for (i = 0; i < QMAIL_LINES_PER_READ; i++)
                  qmail_lines[i] = NULL;
              else
                {
                QRV_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char *) * QMAIL_LINES_PER_READ);
                return_value = DECISION_ERROR;
                continue_processing = 0;
                break;
                }
              }

            if ((max_line == -1) ||
                (total_lines < max_line))
              if (current_line >= num_lines)
                {
                for (i = 0; i < QMAIL_LINES_PER_READ; i++)
                  if (qmail_lines[i] != NULL)
                    {
                    free(qmail_lines[i]);
                    qmail_lines[i] = NULL;
                    }

                if (((num_lines = read_file(current_settings, tmp_path, (char ***)&qmail_lines, 0, last_line + 1, QMAIL_LINES_PER_READ, 1)) > 1) &&
                    (qmail_lines[0] != NULL))
                  {
                  num_lines--;
                  current_line = 0;
                  last_line += num_lines;

                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CURRENT_LINE, qmail_lines[current_line]);
                  current_step = 40;
                  }
                else if (num_lines == -1)
                  {
                  QRV_LOG_VERBOSE(current_settings, LOG_VERBOSE_RECIPIENT_PERMISSION, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), tmp_path);
                  continue_processing = 0;
                  }
                else
                  {
                  if (return_value == DECISION_UNKNOWN)
                    {
                    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
                    return_value = DECISION_INVALID;
                    }

                  continue_processing = 0;
                  }
                }
              else
                {
                QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CURRENT_LINE, qmail_lines[current_line]);
                current_step = 40;
                }
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }

            break;
          case 40:
            found_match = 0;
            if (qmail_lines[current_line][0] != QMAIL_COMMENT)
              for (i = 0; qmail_lines[current_line][i] != '\0'; i++)
                if (!isspace((int)qmail_lines[current_line][i]))
                  {
                  found_match = 1;
                  break;
                  }

            if (found_match)
              current_step = 41;
            else
              {
              current_line++;
              current_step = 39;
              }

            break;
          case 41:
            for (i = 0; qmail_lines[current_line][i] != '\0'; i++);
            if ((strchr(QMAIL_MBOX_START_CHARS, qmail_lines[current_line][0]) != NULL) &&
                (i > 0) &&
                (qmail_lines[current_line][i - 1] != QMAIL_MBOX_END_NOT_CHAR))
              {
              snprintf(tmp_qmail_filename, MAX_PATH, "%s", qmail_lines[current_line]);
              current_step = 42;
              }
            else
              current_step = 44;

            break;
          case 42:
            if (!forward_only)
              current_step = 43;
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }

            break;
          case 43:
            if (tmp_qmail_filename[0] == DIR_DELIMITER)
              tmp_return = check_path_perms(current_settings, tmp_qmail_filename, S_IFREG, FILE_PERMISSION_WRITE, NULL, tmp_uid, tmp_gid);
            else
              {
              snprintf(tmp_unreal_path, MAX_PATH, "%s/%s", qmail_home, tmp_qmail_filename);
              realpath(tmp_unreal_path, tmp_qmail_path);
              tmp_return = check_path_perms(current_settings, tmp_qmail_path, S_IFREG, FILE_PERMISSION_WRITE, NULL, tmp_uid, tmp_gid);
              }

            if (tmp_return == 1)
              {
              return_value = DECISION_VALID;
              continue_processing = 0;
              }
            else if (tmp_return == 0)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 44:
            for (i = 0; qmail_lines[current_line][i] != '\0'; i++);
            if ((strchr(QMAIL_MAILDIR_START_CHARS, qmail_lines[current_line][0]) != NULL) &&
                (i > 0) &&
                (qmail_lines[current_line][i - 1] == QMAIL_MAILDIR_END_CHAR))
              {
              snprintf(tmp_qmail_filename, MAX_PATH, "%s", qmail_lines[current_line]);
              current_step = 45;
              }
            else
              current_step = 47;

            break;
          case 45:
            if (!forward_only)
              current_step = 46;
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }

            break;
          case 46:
            if (tmp_qmail_filename[0] == DIR_DELIMITER)
              snprintf(tmp_qmail_path, MAX_PATH, "%snew", tmp_qmail_filename);
            else
              {
              snprintf(tmp_unreal_path, MAX_PATH, "%s/%snew", qmail_home, tmp_qmail_filename);
              realpath(tmp_unreal_path, tmp_qmail_path);
              }

            if ((tmp_return = check_path_perms(current_settings, tmp_qmail_path, S_IFDIR, FILE_PERMISSION_WRITE, NULL, tmp_uid, tmp_gid)) == 1)
              {
              return_value = DECISION_VALID;
              continue_processing = 0;
              }
            else if (tmp_return == 0)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 47:
            if (qmail_lines[current_line][0] == QMAIL_PROGRAM_START_CHAR)
              {
              find_command(qmail_lines[current_line] + 1, tmp_qmail_filename, MAX_PATH);
              current_step = 48;
              }
            else
              current_step = 66;

            break;
          case 48:
            if (!forward_only)
              current_step = 49;
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }

            break;
          case 49:
            if ((tmp_return = find_path_perms(current_settings, tmp_qmail_filename, S_IFREG, FILE_PERMISSION_EXECUTE, tmp_uid, tmp_gid)) == 1)
              {
              current_step = 50;
              }
            else if (tmp_return == 0)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }
            else
              {
              return_value = DECISION_ERROR;
              continue_processing = 0;
              }

            break;
          case 50:
            tmp_strlen_command = strlen(tmp_qmail_filename);
            if (!strncmp(tmp_qmail_filename + (tmp_strlen_command - STRLEN(VPOPMAIL_VDELIVERMAIL)), VPOPMAIL_VDELIVERMAIL, STRLEN(VPOPMAIL_VDELIVERMAIL)))
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VPOPMAIL_FILE, current_line);

              tmp_strlen = strlen(qmail_lines[current_line]);

              /* Skip trailing spaces */
              for (i = tmp_strlen - 1; i >= (tmp_strlen_command + 1); i--)
                if (!isspace((int)qmail_lines[current_line][i]))
                  break;

              found_match = 0;
              tmp_last_parameter = 0;
              /* Search for the last parameter to vdelivermail, counting spaces along the way */
              while (i >= (tmp_strlen_command + 1))
                if (isspace((int)qmail_lines[current_line][i]))
                  {
                  if (tmp_last_parameter == 0)
                    tmp_last_parameter = i + 1;

                  found_match++;
                  i--;

                  while ((i >= (tmp_strlen_command + 1)) &&
                         isspace((int)qmail_lines[current_line][i]))
                    i--;
                  }
                else
                  i--;

              if (found_match == 2)
                current_step = 51;
              else
                {
                return_value = DECISION_VALID;
                continue_processing = 0;
                }
              }
            else
              {
              return_value = DECISION_VALID;
              continue_processing = 0;
              }

            break;
          case 51:
            if (assign_wildcard_domain_hyphen &&
                virtualdomains_domain_only &&
                !percent_in_username)
              current_step = 52;
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }

            break;
          case 52:

#ifdef WITH_VPOPMAIL_SUPPORT

            current_step = 53;

#else /* WITH_VPOPMAIL_SUPPORT */

            return_value = DECISION_VALID;
            continue_processing = 0;

#endif /* WITH_VPOPMAIL_SUPPORT */

            break;

#ifdef WITH_VPOPMAIL_SUPPORT

          case 53:
            tmp_argv[0] = VPOPMAIL_VALIAS;
            tmp_argv[1] = VPOPMAIL_VALIAS_ARG;
            tmp_argv[2] = reassemble_address(vpopmail_username, strlen_vpopmail_username, vpopmail_domain, NULL, tmp_address, MAX_ADDRESS, NULL);
            tmp_argv[3] = NULL;

            if ((exec_command_argv(current_settings, VPOPMAIL_VALIAS_PATH, tmp_argv, vpopmail_output, MAX_BUF, &tmp_status, tmp_uid, tmp_gid) != -1) &&
                (tmp_status == 0))
              {
              tmp_strlen_output = strlen(vpopmail_output);
              vpopmail_output_ptr = NULL;

              current_step = 54;
              }
            else
              current_step = 58;

            break;
          case 54:
            /*
             * The first time this state is entered, vpopmail_output_ptr will be NULL, so start at the beginning.
             * In subsequent runs, it will point to the start of the next forward address or possibly beyond the
             * end of the buffer.
             */
            if (vpopmail_output_ptr == NULL)
              vpopmail_output_ptr = vpopmail_output;

            found_match = 0;
            while ((vpopmail_output_ptr - vpopmail_output) < (tmp_strlen_output - (STRLEN(VPOPMAIL_VALIAS_DELIMITER) + 1)))
              if ((vpopmail_output_ptr[0] == VPOPMAIL_VALIAS_DELIMITER[0]) &&
                  !strncmp(vpopmail_output_ptr, VPOPMAIL_VALIAS_DELIMITER, STRLEN(VPOPMAIL_VALIAS_DELIMITER)))
                {
                QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIAS_ADDRESS, vpopmail_output_ptr - vpopmail_output, vpopmail_output_ptr + STRLEN(VPOPMAIL_VALIAS_DELIMITER));

                vpopmail_output_ptr += STRLEN(VPOPMAIL_VALIAS_DELIMITER);
                if (vpopmail_output_ptr[0] == QMAIL_FORWARD_START_CHAR)
                  vpopmail_output_ptr++;

                for (i = 0; (vpopmail_output_ptr[i] != '\0') && (vpopmail_output_ptr[i] != '\n'); i++);
                vpopmail_output_ptr[i] = '\0';

                found_match = 1;
                break;
                }
              else
                vpopmail_output_ptr++;

            if (found_match)
              current_step = 55;
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }

            break;
          case 55:
            if (!compare_addresses(current_settings, vpopmail_output_ptr, vpopmail_username, strlen_vpopmail_username, vpopmail_domain, strlen_vpopmail_domain))
              {
              /* FIXME: Should this use find_address() instead? */
              for (i = 0; (vpopmail_output_ptr[i] != '\0') && (vpopmail_output_ptr[i] != '@'); i++);
              tmp_strlen = (vpopmail_output_ptr[i] == '@') ? strlen(vpopmail_output_ptr + i + 1) : 0;

              snprintf(forward_domain, MAX_ADDRESS, "%.*s", tmp_strlen, vpopmail_output_ptr + i + 1);
              strlen_forward_domain = tmp_strlen;

              current_step = 56;
              }
            else
              {
              vpopmail_output_ptr += strlen_recipient_username + ((strlen_recipient_domain > 0) ? (strlen_recipient_domain + 1) : 0) + 1;
              current_step = 54;
              }

            break;
          case 56:
            found_match = 0;
            if (current_settings->qmail_locals_file != NULL)
              for (i = 0; current_settings->qmail_locals_file[i] != NULL; i++)
                {
                if ((tmp_return = search_file(current_settings, current_settings->qmail_locals_file[i], forward_domain, strlen_forward_domain, '\0', NULL, '\0', NULL)) > 0)
                  {
                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_LOCALS_FILE, current_settings->qmail_locals_file[i], forward_domain);
                  found_match = 1;
                  break;
                  }
                else if (tmp_return == -1)
                  {
                  continue_processing = 0;
                  break;
                  }
                }

            if (found_match)
              current_step = 57;
            else
              {
              return_value = DECISION_VALID;
              continue_processing = 0;
              }

            break;
          case 57:
            for (i = 0; (vpopmail_output_ptr[i] != '\0') && (vpopmail_output_ptr[i] != '@'); i++);
            vpopmail_output_ptr[i] = '\0';

            if (((return_value = validate(current_settings, vpopmail_output_ptr, i, forward_domain, &current)) == DECISION_VALID) ||
                (return_value == DECISION_ERROR))
              continue_processing = 0;
            else
              {
              vpopmail_output_ptr += i + ((strlen_working_domain > 0) ? (strlen_working_domain + 1) : 0) + 1;
              current_step = 54;
              }

            break;
          case 58:
            tmp_argv[0] = VPOPMAIL_VUSERINFO;
            tmp_argv[1] = VPOPMAIL_VUSERINFO_ARG;
            tmp_argv[2] = reassemble_address(vpopmail_username, strlen_vpopmail_username, vpopmail_domain, NULL, tmp_address, MAX_ADDRESS, NULL);
            tmp_argv[3] = NULL;

            /*
             * vuserinfo return codes:
             *   -1: user not found
             *    0: user found
             *    1: error
             */
            if (exec_command_argv(current_settings, VPOPMAIL_VUSERINFO_PATH, tmp_argv, vpopmail_output, MAX_BUF, &tmp_status, tmp_uid, tmp_gid) != -1)
              {
              if (tmp_status == 0)
                {
                return_value = DECISION_VALID;
                continue_processing = 0;
                }
              else
                current_step = 59;
              }
            else
              {
              return_value = DECISION_VALID;
              continue_processing = 0;
              }
            break;
          case 59:
            if (!strncmp(qmail_lines[current_line] + tmp_last_parameter, VPOPMAIL_BOUNCE, STRLEN(VPOPMAIL_BOUNCE)))
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }
            else
              current_step = 60;

            break;
          case 60:
            if (!strncmp(qmail_lines[current_line] + tmp_last_parameter, VPOPMAIL_DELETE, STRLEN(VPOPMAIL_DELETE)))
              {
              return_value = DECISION_VALID;
              continue_processing = 0;
              }
            else
              current_step = 61;

            break;
          case 61:
            if (qmail_lines[current_line][tmp_last_parameter] == DIR_DELIMETER)
              current_step = 65;
            else
              current_step = 62;

            break;
          case 62:
            if (!compare_addresses(current_settings, qmail_lines[current_line] + tmp_last_parameter, working_username, strlen_working_username, working_domain, strlen_working_domain))
              {
              /* FIXME: Should this use find_address() instead? */
              for (i = tmp_last_parameter; (qmail_lines[current_line][i] != '\0') && (qmail_lines[current_line][i] != '@'); i++);
              tmp_strlen = (qmail_lines[current_line][i] == '@') ? strlen(qmail_lines[current_line] + i + 1) : 0;

              snprintf(forward_domain, MAX_ADDRESS, "%.*s", tmp_strlen, qmail_lines[current_line] + i + 1);
              strlen_forward_domain = tmp_strlen;

              current_step = 63;
              }
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_INVALID_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_INVALID;
              continue_processing = 0;
              }

            break;
          case 63:
            found_match = 0;
            if (current_settings->qmail_locals_file != NULL)
              for (i = 0; current_settings->qmail_locals_file[i] != NULL; i++)
                {
                if ((tmp_return = search_file(current_settings, current_settings->qmail_locals_file[i], forward_domain, strlen_forward_domain, '\0', NULL, '\0', NULL)) > 0)
                  {
                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_LOCALS_FILE, current_settings->qmail_locals_file[i], forward_domain);
                  found_match = 1;
                  break;
                  }
                else if (tmp_return == -1)
                  {
                  continue_processing = 0;
                  break;
                  }
                }

            if (found_match)
              current_step = 64;
            else
              {
              return_value = DECISION_VALID;
              continue_processing = 0;
              }

            break;
          case 64:
            for (i = tmp_last_parameter; (qmail_lines[current_line][i] != '\0') && (qmail_lines[current_line][i] != '@'); i++);
            qmail_lines[current_line][i] = '\0';

            if (((return_value = validate(current_settings, qmail_lines[current_line] + tmp_last_parameter, i, forward_domain, &current)) == DECISION_VALID) ||
                (return_value == DECISION_ERROR))
              continue_processing = 0;
            else
              {
              current_line++;
              current_step = 39;
              }

            break;
          case 65:
            tmp_strlen = strlen(qmail_lines[current_line]);
            snprintf(tmp_qmail_path, MAX_PATH, "%s%s%snew", qmail_lines[current_line] + tmp_last_parameter, (qmail_lines[current_line][tmp_strlen - 1] == '/') ? "" : "/", VPOPMAIL_VDELIVERMAIL_MAILDIR);

            if ((tmp_return = check_path_perms(current_settings, tmp_qmail_path, S_IFDIR, FILE_PERMISSION_WRITE, NULL, tmp_uid, tmp_gid)) == 1)
              {
              return_value = DECISION_VALID;
              continue_processing = 0;
              }
            else
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT, reassemble_address(current_settings->recipient_username, -1, current_settings->recipient_domain, NULL, tmp_address, MAX_ADDRESS, NULL), working_username);
              return_value = DECISION_UNAVAILABLE;
              continue_processing = 0;
              }
            break;

#endif /* WITH_VPOPMAIL_SUPPORT */

          case 66:
            if (!compare_addresses(current_settings, qmail_lines[current_line] + ((qmail_lines[current_line][0] == QMAIL_FORWARD_START_CHAR) ? 1 : 0), working_username, strlen_working_username, working_domain, strlen_working_domain))
              {
              /* FIXME: Should this use find_address() instead? */
              for (i = 0; (qmail_lines[current_line][i] != '\0') && (qmail_lines[current_line][i] != '@'); i++);
              tmp_strlen = (qmail_lines[current_line][i] == '@') ? strlen(qmail_lines[current_line] + i + 1) : 0;

              snprintf(forward_domain, MAX_ADDRESS, "%.*s", tmp_strlen, qmail_lines[current_line] + i + 1);
              strlen_forward_domain = tmp_strlen;

              current_step = 67;
              }
            else
              {
              current_line++;
              current_step = 39;
              }

            break;
          case 67:
            found_match = 0;
            if (current_settings->qmail_locals_file != NULL)
              for (i = 0; current_settings->qmail_locals_file[i] != NULL; i++)
                {
                if ((tmp_return = search_file(current_settings, current_settings->qmail_locals_file[i], forward_domain, strlen_forward_domain, '\0', NULL, '\0', NULL)) > 0)
                  {
                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_LOCALS_FILE, current_settings->qmail_locals_file[i], forward_domain);
                  found_match = 1;
                  break;
                  }
                else if (tmp_return == -1)
                  {
                  continue_processing = 0;
                  break;
                  }
                }

            if (found_match)
              current_step = 68;
            else
              {
              return_value = DECISION_VALID;
              continue_processing = 0;
              }

            break;
          case 68:
            for (i = 0; (qmail_lines[current_line][i] != '\0') && (qmail_lines[current_line][i] != '@'); i++);

            if (((return_value = validate(current_settings, qmail_lines[current_line] + ((qmail_lines[current_line][0] == QMAIL_FORWARD_START_CHAR) ? 1 : 0), (qmail_lines[current_line][i] == '@') ? (i - 1) : i, (qmail_lines[current_line][i] == '@') ? (qmail_lines[current_line] + i + 1) : "", &current)) == DECISION_VALID) ||
                (return_value == DECISION_ERROR))
              continue_processing = 0;
            else
              {
              current_line++;
              current_step = 39;
              }

            break;
          default:
            QRV_LOG_ERROR(current_settings, LOG_ERROR_INVALID_STATE, current_step, strlen_working_username, working_username, working_domain, tmp_name, tmp_filename, tmp_path, qmail_dash, qmail_ext);
            return_value = DECISION_ERROR;
            continue_processing = 0;
          }
        }

      endpwent();

      if (qmail_lines != NULL)
        {
        for (i = 0; i < QMAIL_LINES_PER_READ; i++)
          if (qmail_lines[i] != NULL)
            free(qmail_lines[i]);

        free(qmail_lines);
        }

      if (tmp_file_line != NULL)
        free(tmp_file_line);
      }
    else
      QRV_LOG_VERBOSE(current_settings, LOG_VERBOSE_VALIDATE_DEPTH, reassemble_address(target_recipient_username, -1, target_recipient_domain, LOG_DATA_NULL, tmp_address, MAX_ADDRESS, NULL), forward_depth);
    }

  if ((last == NULL) &&
      current_settings->diag)
    QRV_DIAG(current_settings, LOG_DIAG_DECISION_PATH, strlen_decision_path, decision_path);

  return(return_value);
  }
