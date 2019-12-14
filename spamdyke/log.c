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
#include <stdarg.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
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
#include "tls.h"
#include "log.h"

/*
 * Expects:
 *   action ==
 *     LOG_ACTION_LOG_IP - insert log header showing remote server's IP address, no data
 *     LOG_ACTION_LOG_RDNS - insert log header showing remote server's rDNS name, no data
 *     LOG_ACTION_TLS_PASSTHROUGH_START - insert log header showing TLS passthrough has begun, no data
 *     LOG_ACTION_AUTH_FAILURE - insert log header showing SMTP AUTH was attempted but failed, no data
 *     LOG_ACTION_AUTH_SUCCESS - insert log header showing SMTP AUTH was successful, username is stored in current_settings->smtp_auth_username, no data
 *     LOG_ACTION_TLS_START - insert log header showing TLS session has begun, no data
 *     LOG_ACTION_TLS_END - insert log header showing TLS session has ended, no data
 *     LOG_ACTION_NONE - no header, do not log
 *     LOG_ACTION_REMOTE_FROM - log data from remote to child
 *     LOG_ACTION_CHILD_FROM - log data from child to remote
 *     LOG_ACTION_CHILD_FROM_DISCARDED - log discarded data from child to remote
 *     LOG_ACTION_FILTER_FROM - log data injected by spamdyke to remote
 *     LOG_ACTION_FILTER_TO - log data injected by spamdyke to child
 *     LOG_ACTION_LOG_OUTPUT - log data sent to syslog/stderr
 *     LOG_ACTION_CURRENT_CONFIG - no timestamp for successive calls, log current effective configuration options
 *     LOG_ACTION_CURRENT_ENVIRONMENT - no timestamp for successive calls, log current environment variables/values
 *   target_fd == file descriptor destination for data or -1 if data should not be output
 *
 * Return value:
 *   ERROR: -1
 *   SUCCESS: bytes output to target_fd
 */
int output_writeln(struct filter_settings *current_settings, int action, int target_fd, char *data, int data_length)
  {
  static FILE *log_file = NULL;
  static char *prefixes[] = LOG_ACTION_PREFIX;
  static char last_char = '\0';
  static int last_action = LOG_ACTION_NONE;
  static char log_filename[MAX_BUF + 1] = { '\0' };
  int return_value;
  int i;
  struct tm *tmp_tm;
  time_t tmp_time;
  char *data_ptr;
  char *data_last;
  int inserted_data_length;

  return_value = 0;
  inserted_data_length = 0;

  if ((target_fd >= 0) &&
      (data_length > 0))
    {
    if ((action == LOG_ACTION_CHILD_FROM) ||
        (action == LOG_ACTION_FILTER_FROM))
      {
      if ((return_value = NETWORK_WRITE(current_settings, target_fd, data, data_length)) != -1)
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_REMOTE_WRITE, return_value, target_fd, data_length, MINVAL(data_length, LOG_DEBUGX_STRLEN_PREVIEW), data);
      else
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_WRITE "%s", data_length, target_fd, strerror(errno));
      }
    else if (current_settings->tls_state == TLS_STATE_ACTIVE_PASSTHROUGH)
      {
      if ((return_value = write(target_fd, data, data_length)) == -1)
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_WRITE "%s", data_length, target_fd, strerror(errno));
      }
    else
      {
      /*
       * This loop examines the data as it is sent and turns any bare LFs into
       * CRLF.  The data_last pointer tracks the start of the data that hasn't
       * been sent yet -- the data is only sent line-by-line if CRs must be
       * inserted.  Otherwise it is bursted (assuming data contains more than
       * one line).
       */
      data_ptr = data;
      data_last = data;
      while ((data_ptr - data) < data_length)
        {
        for (i = 0; (((data_ptr - data) + i) < data_length) && (data_ptr[i] != CHAR_LF); i++);
        if (((data_ptr - data) + i) < data_length)
          {
          if (((((data_ptr - data) + i) > 0) &&
               (data[(data_ptr - data) + (i - 1)] != CHAR_CR)) ||
              ((((data_ptr - data) + i) == 0) &&
               (last_char != CHAR_CR)))
            {
            if (i > 0)
              {
              if ((return_value = write(target_fd, data_last, (data_ptr - data_last) + i)) != -1)
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CHILD_WRITE_CRLF, return_value, target_fd, data_length, MINVAL((data_ptr - data_last) + i, LOG_DEBUGX_STRLEN_PREVIEW), data_last);
              else
                {
                SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_WRITE "%s", i, target_fd, strerror(errno));
                break;
                }
              }

            data_last = data_ptr + i + 1;

            if ((return_value = write(target_fd, STR_CRLF, STRLEN(STR_CRLF))) == -1)
              {
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_WRITE "%s", STRLEN(STR_CRLF), target_fd, strerror(errno));
              break;
              }

            inserted_data_length++;
            }
          else
            if ((return_value = write(target_fd, data_last, (data_ptr - data_last) + i + 1)) != -1)
              {
              SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CHILD_WRITE, return_value, target_fd, data_length, MINVAL((data_ptr - data_last) + i + 1, LOG_DEBUGX_STRLEN_PREVIEW), data_last);
              data_last = data_ptr + i + 1;
              }
            else
              {
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_WRITE "%s", i + 1, target_fd, strerror(errno));
              break;
              }

          data_ptr += i + 1;
          }
        else
          {
          if ((return_value = write(target_fd, data_last, (data_ptr - data_last) + i)) != -1)
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CHILD_WRITE, return_value, target_fd, data_length, MINVAL((data_ptr - data_last) + i, LOG_DEBUGX_STRLEN_PREVIEW), data_last);
          else
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_WRITE "%s", i, target_fd, strerror(errno));

          break;
          }
        }

      last_char = data[data_length - 1];
      }
    }
  else
    {
    return_value = 0;
    last_char = '\0';
    }

  if (action != LOG_ACTION_NONE)
    {
    tmp_tm = NULL;

    if ((current_settings == NULL) &&
        (log_file != NULL))
      {
      tmp_time = time(NULL);
      tmp_tm = localtime(&tmp_time);

      if (fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d CLOSED\n", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec) == -1)
        SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));

      fclose(log_file);
      log_file = NULL;
      }
    else if ((current_settings != NULL) &&
             (current_settings->current_options->log_dir != NULL) &&
             (log_file == NULL) &&
             (log_filename[0] == '\0'))
      {
      tmp_time = time(NULL);
      tmp_tm = localtime(&tmp_time);

      snprintf(log_filename, MAX_BUF, "%s" DIR_DELIMITER_STR "%d%.2d%.2d_%.2d%.2d%.2d_" FORMAT_PID_T "_%ld", current_settings->current_options->log_dir, tmp_tm->tm_year + 1900, tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec, getpid(), random());

      if ((log_file = fopen(log_filename, "w")) != NULL)
        {
        chmod(log_filename, CHMOD_MODE);
        if (fprintf(log_file, "%.2d/%.2d/%d %.2d:%.2d:%.2d STARTED: VERSION = %s, PID = " FORMAT_PID_T "\n", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec, VERSION_STRING, getpid()) == -1)
          {
          SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
          fclose(log_file);
          log_file = NULL;
          }
        }
      else
        SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_OPEN_LOG "%s: %s", log_filename, strerror(errno));
      }

    if (log_file != NULL)
      {
      if (tmp_tm == NULL)
        {
        tmp_time = time(NULL);
        tmp_tm = localtime(&tmp_time);
        }

      switch (action)
        {
        case LOG_ACTION_TLS_PASSTHROUGH_START:
          if ((fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec) == -1) ||
              ((current_settings->smtp_auth_username[0] != '\0') &&
               (fprintf(log_file, LOG_ACTION_PREFIX_AUTH "%s", current_settings->smtp_auth_username) == -1)) ||
              (fprintf(log_file, " - %s\n", LOG_MESSAGE_TLS_PASSTHROUGH_START) == -1))
            {
            SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
            fclose(log_file);
            log_file = NULL;
            }

          break;
        case LOG_ACTION_TLS_START:
          if ((fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec) == -1) ||
              ((current_settings->smtp_auth_username[0] != '\0') &&
               (fprintf(log_file, LOG_ACTION_PREFIX_AUTH "%s", current_settings->smtp_auth_username) == -1)) ||
              (fprintf(log_file, " - %s\n", LOG_MESSAGE_TLS_START) == -1))
            {
            SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
            fclose(log_file);
            log_file = NULL;
            }

          break;
        case LOG_ACTION_TLS_END:
          if ((fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec) == -1) ||
              ((current_settings->smtp_auth_username[0] != '\0') &&
               (fprintf(log_file, LOG_ACTION_PREFIX_AUTH "%s", current_settings->smtp_auth_username) == -1)) ||
              (fprintf(log_file, " - %s\n", LOG_MESSAGE_TLS_END) == -1))
            {
            SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
            fclose(log_file);
            log_file = NULL;
            }

          break;
        case LOG_ACTION_AUTH_SUCCESS:
          if ((fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec) == -1) ||
              ((current_settings->tls_state == TLS_STATE_ACTIVE_SPAMDYKE) &&
               (fprintf(log_file, LOG_ACTION_PREFIX_TLS_SPAMDYKE) == -1)) ||
              ((current_settings->tls_state == TLS_STATE_ACTIVE_PASSTHROUGH) &&
               (fprintf(log_file, LOG_ACTION_PREFIX_TLS_PASSTHROUGH) == -1)) ||
              ((current_settings->smtp_auth_username[0] != '\0') &&
               (fprintf(log_file, LOG_ACTION_PREFIX_AUTH "%s", (current_settings->smtp_auth_username[0] != '\0') ? current_settings->smtp_auth_username : LOG_MISSING_DATA) == -1)) ||
              (fprintf(log_file, " - %s\n", LOG_MESSAGE_AUTH_SUCCESS) == -1))
            {
            SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
            fclose(log_file);
            log_file = NULL;
            }

          break;
        case LOG_ACTION_AUTH_FAILURE:
          if ((fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec) == -1) ||
              ((current_settings->tls_state == TLS_STATE_ACTIVE_SPAMDYKE) &&
               (fprintf(log_file, LOG_ACTION_PREFIX_TLS_SPAMDYKE) == -1)) ||
              ((current_settings->tls_state == TLS_STATE_ACTIVE_PASSTHROUGH) &&
               (fprintf(log_file, LOG_ACTION_PREFIX_TLS_PASSTHROUGH) == -1)) ||
              (fprintf(log_file, " - %s%s\n", LOG_MESSAGE_AUTH_FAILURE, data) == -1))
            {
            SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
            fclose(log_file);
            log_file = NULL;
            }

          break;
        case LOG_ACTION_LOG_IP:
          if (fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d - %s%.*s\n", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec, LOG_MESSAGE_REMOTE_IP, (current_settings->strlen_server_ip > 0) ? current_settings->strlen_server_ip : (int)STRLEN(LOG_MISSING_DATA), (current_settings->strlen_server_ip > 0) ? current_settings->server_ip : LOG_MISSING_DATA) == -1)
            {
            SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
            fclose(log_file);
            log_file = NULL;
            }

          break;
        case LOG_ACTION_LOG_RDNS:
          if (fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d - %s%.*s\n", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec, LOG_MESSAGE_RDNS_NAME, (current_settings->strlen_server_name > 0) ? current_settings->strlen_server_name : (int)STRLEN(LOG_MISSING_DATA), (current_settings->strlen_server_name > 0) ? current_settings->server_name : LOG_MISSING_DATA) == -1)
            {
            SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
            fclose(log_file);
            log_file = NULL;
            }

          break;
        case LOG_ACTION_LOG_OUTPUT:
        case LOG_ACTION_CURRENT_CONFIG:
        case LOG_ACTION_CURRENT_ENVIRONMENT:
          if ((last_action != action) &&
              ((fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d %s", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec, prefixes[action]) == -1) ||
               ((current_settings->tls_state == TLS_STATE_ACTIVE_SPAMDYKE) &&
                (fprintf(log_file, LOG_ACTION_PREFIX_TLS_SPAMDYKE) == -1)) ||
               ((current_settings->tls_state == TLS_STATE_ACTIVE_PASSTHROUGH) &&
                (fprintf(log_file, LOG_ACTION_PREFIX_TLS_PASSTHROUGH) == -1)) ||
               ((current_settings->smtp_auth_username[0] != '\0') &&
                (fprintf(log_file, LOG_ACTION_PREFIX_AUTH "%s", current_settings->smtp_auth_username) == -1)) ||
               (fprintf(log_file, "\n") == -1)))
            {
            SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
            fclose(log_file);
            log_file = NULL;
            }

          break;
        default:
          if ((fprintf(log_file, "\n%.2d/%.2d/%d %.2d:%.2d:%.2d %s: %d bytes", tmp_tm->tm_mon + 1, tmp_tm->tm_mday, tmp_tm->tm_year + 1900, tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec, prefixes[action], data_length + inserted_data_length) == -1) ||
              ((current_settings->tls_state == TLS_STATE_ACTIVE_SPAMDYKE) &&
               (fprintf(log_file, LOG_ACTION_PREFIX_TLS_SPAMDYKE) == -1)) ||
              ((current_settings->tls_state == TLS_STATE_ACTIVE_PASSTHROUGH) &&
               (fprintf(log_file, LOG_ACTION_PREFIX_TLS_PASSTHROUGH) == -1)) ||
              ((current_settings->smtp_auth_username[0] != '\0') &&
               (fprintf(log_file, LOG_ACTION_PREFIX_AUTH "%s", current_settings->smtp_auth_username) == -1)) ||
              (fprintf(log_file, "\n") == -1))
            {
            SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG "%s", log_filename, strerror(errno));
            fclose(log_file);
            log_file = NULL;
            }

          break;
        }

      if (data_length >= 0)
        {
        if (current_settings->tls_state == TLS_STATE_ACTIVE_PASSTHROUGH)
          {
          int i;

          for (i = 0; i < data_length; i++)
            if (fprintf(log_file, "%.2x ", data[i]) == -1)
              {
              SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_LOG, log_filename, strerror(errno));
              fclose(log_file);
              log_file = NULL;
              break;
              }
          }
        else
          {
          /*
           * This loop examines the data as it is sent and turns any bare LFs into
           * CRLF.  The data_last pointer tracks the start of the data that hasn't
           * been sent yet -- the data is only sent line-by-line if CRs must be
           * inserted.  Otherwise it is bursted (assuming data contains more than
           * one line).
           */
          data_ptr = data;
          data_last = data;
          while ((data_ptr - data) < data_length)
            {
            for (i = 0; (((data_ptr - data) + i) < data_length) && (data_ptr[i] != CHAR_LF); i++);
            if (((data_ptr - data) + i) < data_length)
              {
              if (((((data_ptr - data) + i) > 0) &&
                   (data[(data_ptr - data) + (i - 1)] != CHAR_CR)) ||
                  ((((data_ptr - data) + i) == 0) &&
                   (last_char != CHAR_CR)))
                {
                if ((i > 0) &&
                    (fprintf(log_file, "%.*s", (int)((data_ptr - data_last) + i), data_last) == -1))
                  {
                  SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_BYTES "%s", (data_ptr - data_last) + i, log_filename, strerror(errno));
                  fclose(log_file);
                  log_file = NULL;
                  break;
                  }

                data_last = data_ptr + i + 1;

                if (fprintf(log_file, "%.*s", STRLEN(STR_CRLF), STR_CRLF) == -1)
                  {
                  SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_BYTES "%s", STRLEN(STR_CRLF), log_filename, strerror(errno));
                  fclose(log_file);
                  log_file = NULL;
                  break;
                  }

                inserted_data_length++;
                }
              else
                if (fprintf(log_file, "%.*s", (int)((data_ptr - data_last) + i + 1), data_last) != -1)
                  data_last = data_ptr + i + 1;
                else
                  {
                  SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_BYTES "%s", (data_ptr - data_last) + i + 1, log_filename, strerror(errno));
                  fclose(log_file);
                  log_file = NULL;
                  break;
                  }

              data_ptr += i + 1;
              }
            else
              {
              if (fprintf(log_file, "%.*s", (int)((data_ptr - data_last) + i), data_last) == -1)
                {
                SPAMDYKE_RELOG_ERROR(current_settings, LOG_ERROR_FPRINTF_BYTES "%s", (data_ptr - data_last) + i, log_filename, strerror(errno));
                fclose(log_file);
                log_file = NULL;
                }

              break;
              }
            }

          last_char = data[data_length - 1];
          }
        }
      }

    fflush(NULL);
    }

  last_action = action;

  return(return_value);
  }

/*
 * Expects:
 *   if format == NULL, syslog is closed
 */
void spamdyke_log(struct filter_settings *current_settings, int target_level, int output_to_full_log, char *format, ...)
  {
  static int syslog_initialized = 0;
  char tmp_data[MAX_BUF + 1];
  int strlen_data;
  int syslog_level;
  va_list tmp_va;

  if (format != NULL)
    {
    if ((current_settings != NULL) &&
        (current_settings->current_options != NULL))
      {
      if (current_settings->current_options->log_level >= target_level)
        {
        if (current_settings->current_options->log_target == LOG_USE_CONFIG_TEST)
          {
          va_start(tmp_va, format);

          snprintf(tmp_data, MAX_BUF, "%s\n", format);
          vfprintf(stderr, tmp_data, tmp_va);

          va_end(tmp_va);
          }
        else
          {
          if ((current_settings->current_options->log_target & LOG_USE_SYSLOG) != 0)
            {
            if (!syslog_initialized)
              {
              openlog(SYSLOG_IDENTIFIER, LOG_PID, LOG_MAIL);
              syslog_initialized = 1;
              }

            switch (target_level)
              {
              case LOG_LEVEL_ERROR:
                syslog_level = LOG_ERR;
                break;
              case LOG_LEVEL_DEBUG:
                syslog_level = LOG_DEBUG;
                break;
              default:
                syslog_level = LOG_INFO;
                break;
              }

            va_start(tmp_va, format);
            vsnprintf(tmp_data, MAX_BUF, format, tmp_va);
            syslog(syslog_level, "%s", tmp_data);
            va_end(tmp_va);
            }

          if ((current_settings->current_options->log_target & LOG_USE_STDERR) != 0)
            {
            va_start(tmp_va, format);

            snprintf(tmp_data, MAX_BUF, "spamdyke[%d]: %s\n", (int)getpid(), format);
            vfprintf(stderr, tmp_data, tmp_va);

            va_end(tmp_va);
            }
          }
        }

      if (output_to_full_log &&
          (current_settings->current_options->log_dir != NULL))
        {
        va_start(tmp_va, format);

        vsnprintf(tmp_data, MAX_BUF - 1, format, tmp_va);
        if ((strlen_data = strlen(tmp_data)) > 0)
          {
          if (tmp_data[strlen_data - 1] != '\n')
            {
            tmp_data[strlen_data] = '\n';
            tmp_data[strlen_data + 1] = '\0';
            strlen_data++;
            }

          output_writeln(current_settings, LOG_ACTION_LOG_OUTPUT, -1, tmp_data, strlen_data);
          }

        va_end(tmp_va);
        }
      }
    else
      {
      va_start(tmp_va, format);

      snprintf(tmp_data, MAX_BUF, "%s\n", format);
      vfprintf(stderr, tmp_data, tmp_va);

      va_end(tmp_va);
      }

    fflush(NULL);
    }
  else if (syslog_initialized)
    {
    closelog();
    syslog_initialized = 0;
    }

  return;
  }

char *canonicalize_log_text(char *target_buf, int strlen_target_buf, char *input_text, int strlen_input_text)
  {
  char *return_value;
  int i;
  int tmp_strlen;

  return_value = target_buf;

  if ((input_text != NULL) &&
      (target_buf != NULL) &&
      (strlen_target_buf > 0))
    {
    tmp_strlen = MINVAL(strlen_input_text, strlen_target_buf - 1);
    memcpy(target_buf, input_text, tmp_strlen);
    target_buf[tmp_strlen] = '\0';

    for (i = 0; i < tmp_strlen; i++)
      if (target_buf[i] == REASON_REPLACE_TARGET)
        target_buf[i] = REASON_REPLACE_REPLACEMENT;
    }

  return(return_value);
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
