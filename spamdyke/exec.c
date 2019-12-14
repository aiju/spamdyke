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
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <sys/select.h>
#include <stdlib.h>

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
#include "environment.h"
#include "log.h"
#include "configuration.h"
#include "search_fs.h"
#include "exec.h"

/*
 * Return value:
 *   ERROR: 0
 *   SUCCESS: does not return
 */
int exec_path(struct filter_settings *current_settings, char *filename, char *argv[], char *envp[])
  {
  char new_filename[MAX_BUF + 1];

  if (find_path(current_settings, filename, envp, new_filename, MAX_BUF))
    execve(new_filename, argv, envp);

  return(0);
  }

/*
 * Expects:
 *   filename == argv[0]
 *   username may be NULL
 *   password may be NULL
 *   timestamp may be NULL
 *
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int exec_checkpassword_argv(struct filter_settings *current_settings, char *filename, char *argv[], char *username, char *password, char *timestamp)
  {
  int return_value;
  int stdout_pipe[2];
  int stderr_pipe[2];
  int output_pipe[2];
  pid_t child_pid;
  char output_buf[MAX_CHECKPASSWORD + 1];
  int strlen_output_buf;
  int strlen_sent_buf;
  int status;
  fd_set read_fds;
  fd_set write_fds;
  int max_fd;
  struct timeval timeout;
  time_t start_time;
  char tmp_buf[MAX_BUF + 1];
  char new_filename[MAX_BUF + 1];
  int last_wait;

  return_value = 0;
  last_wait = 0;

  if (find_path(current_settings, filename, current_settings->current_environment, new_filename, MAX_BUF))
    if (pipe(output_pipe) != -1)
      if (pipe(stdout_pipe) != -1)
        if (pipe(stderr_pipe) != -1)
          {
          SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_EXEC_CHECKPASSWORD, argv[0], username);

          if ((child_pid = fork()) > 0)
            {
            close(output_pipe[0]);
            close(stdout_pipe[1]);
            close(stderr_pipe[1]);

            strlen_output_buf = SNPRINTF(output_buf, MAX_CHECKPASSWORD, "%s%c%s%c%s%c", (username != NULL) ? username : "", '\0', (password != NULL) ? password : "", '\0', (timestamp != NULL) ? timestamp : "", '\0');
            strlen_sent_buf = 0;

            start_time = time(NULL);

            timeout.tv_sec = TIMEOUT_CHECKPASSWORD_SECS - (time(NULL) - start_time);
            timeout.tv_usec = 0;

            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            FD_SET(output_pipe[1], &write_fds);
            FD_SET(stdout_pipe[0], &read_fds);
            FD_SET(stderr_pipe[0], &read_fds);
            max_fd = MAXVAL(MAXVAL(output_pipe[1], stdout_pipe[0]), stderr_pipe[0]);

            while (select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout) >= 0)
              {
              if ((stdout_pipe[0] >= 0) &&
                  FD_ISSET(stdout_pipe[0], &read_fds) &&
                  (read(stdout_pipe[0], tmp_buf, MAX_BUF) == 0))
                {
                close(stdout_pipe[0]);
                stdout_pipe[0] = -1;
                }

              if ((stderr_pipe[0] >= 0) &&
                  FD_ISSET(stderr_pipe[0], &read_fds) &&
                  (read(stderr_pipe[0], tmp_buf, MAX_BUF) == 0))
                {
                close(stderr_pipe[0]);
                stderr_pipe[0] = -1;
                }

              if ((output_pipe[1] >= 0) &&
                  FD_ISSET(output_pipe[1], &write_fds))
                strlen_sent_buf += write(output_pipe[1], output_buf + strlen_sent_buf, strlen_output_buf - strlen_sent_buf);

              timeout.tv_sec = TIMEOUT_CHECKPASSWORD_SECS - (time(NULL) - start_time);
              timeout.tv_usec = 0;

              if (((last_wait = waitpid(child_pid, &status, WNOHANG)) == 0) &&
                  (timeout.tv_sec > 0))
                {
                FD_ZERO(&read_fds);
                FD_ZERO(&write_fds);
                max_fd = -1;

                if (stdout_pipe[0] >= 0)
                  {
                  FD_SET(stdout_pipe[0], &read_fds);
                  max_fd = stdout_pipe[0];
                  }
                if (stderr_pipe[0] >= 0)
                  {
                  FD_SET(stderr_pipe[0], &read_fds);
                  max_fd = MAXVAL(max_fd, stderr_pipe[0]);
                  }

                if (strlen_sent_buf < strlen_output_buf)
                  {
                  FD_SET(output_pipe[1], &write_fds);
                  max_fd = MAXVAL(max_fd, output_pipe[1]);
                  }
                else if (output_pipe[1] != -1)
                  {
                  close(output_pipe[1]);
                  output_pipe[1] = -1;
                  }

                if (max_fd == -1)
                  timeout.tv_sec = 1;
                }
              else
                break;
              }

            if (((last_wait == child_pid) ||
                 (waitpid(child_pid, &status, WNOHANG) == child_pid)) &&
                WIFEXITED(status))
              {
              /* Status codes are documented at http://cr.yp.to/checkpwd/interface.html */
              switch (WEXITSTATUS(status))
                {
                case 0:
                  /* Success */
                  SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_AUTH_SUCCESS "%s", username);
                  return_value = 1;
                  break;
                case 1:
                  /* Bad username/password */
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_FAILURE "%s", username);
                  break;
                case 2:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_MISUSE "%s", username);
                  break;
                case 3:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_UNKNOWN_USER "%s", WEXITSTATUS(status), username);
                  break;
                case 7:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_ENV_USER "%s", WEXITSTATUS(status), username);
                  break;
                case 8:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_ENV_HOME "%s", WEXITSTATUS(status), username);
                  break;
                case 9:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_ENV_SHELL "%s", WEXITSTATUS(status), username);
                  break;
                case 10:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_ENV_VPOPUSER "%s", WEXITSTATUS(status), username);
                  break;
                case 11:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_BAD_INPUT "%s", WEXITSTATUS(status), username);
                  break;
                case 12:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_NULL_USER "%s", WEXITSTATUS(status), username);
                  break;
                case 13:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_NULL_PASSWORD "%s", WEXITSTATUS(status), username);
                  break;
                case 14:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_HOME_DIR "%s", WEXITSTATUS(status), username);
                  break;
                case 15:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_NO_PASSWORD "%s", WEXITSTATUS(status), username);
                  break;
                case 20:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_BAD_CHARS "%s", WEXITSTATUS(status), username);
                  break;
                case 21:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_UNKNOWN_SYSTEM_USER "%s", WEXITSTATUS(status), username);
                  break;
                case 22:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_UNKNOWN_SYSTEM_SHADOW "%s", WEXITSTATUS(status), username);
                  break;
                case 23:
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_VCHKPW_FAILURE_SYSTEM_USER "%s", WEXITSTATUS(status), username);
                  break;
                case 111:
                  /* Temporary error */
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_ERROR "%s", username);
                  break;
                default:
                  /* Undocumented error code */
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_UNKNOWN "(%d): %s", WEXITSTATUS(status), username);
                  break;
                }
              }
            else
              {
              kill(child_pid, SIGKILL);
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_AUTH_ABEND "%s", username);
              }

            if (output_pipe[1] != -1)
              close(output_pipe[1]);
            if (stdout_pipe[0] != -1)
              close(stdout_pipe[0]);
            if (stderr_pipe[0] != -1)
              close(stderr_pipe[0]);
            }
          else if (child_pid == 0)
            {
            close(output_pipe[1]);
            close(stdout_pipe[0]);
            close(stderr_pipe[0]);

            current_settings->current_options->log_target = LOG_USE_SYSLOG;

            if (dup2(output_pipe[0], CHECKPASSWORD_FD) != -1)
              if (dup2(stdout_pipe[1], STDOUT_FD) != -1)
                if (dup2(stderr_pipe[1], STDERR_FD) != -1)
                  {
                  signal(SIGPIPE, SIG_DFL);

                  execve(new_filename, argv, current_settings->current_environment);

                  SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_EXEC "%s: %s", new_filename, strerror(errno));

                  close(output_pipe[0]);
                  close(stdout_pipe[1]);
                  close(stderr_pipe[1]);

                  exit(111);
                  }
                else
                  {
                  SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MOVE_DESCRIPTORS "%s", strerror(errno));

                  close(output_pipe[0]);
                  close(stdout_pipe[1]);
                  close(stderr_pipe[1]);
                  }
              else
                {
                SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MOVE_DESCRIPTORS "%s", strerror(errno));

                close(output_pipe[0]);
                close(stdout_pipe[1]);
                close(stderr_pipe[1]);
                }
            else
              {
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MOVE_DESCRIPTORS "%s", strerror(errno));

              close(output_pipe[0]);
              close(stdout_pipe[1]);
              close(stderr_pipe[1]);
              }
            }
          else
            {
            SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_FORK "%s", strerror(errno));

            close(stderr_pipe[0]);
            close(stderr_pipe[1]);
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);
            close(output_pipe[0]);
            close(output_pipe[1]);
            }
          }
        else
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_PIPE "%s", strerror(errno));

          close(stdout_pipe[0]);
          close(stdout_pipe[1]);
          close(output_pipe[0]);
          close(output_pipe[1]);
          }
      else
        {
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_PIPE "%s", strerror(errno));

        close(output_pipe[0]);
        close(output_pipe[1]);
        }
    else
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_PIPE "%s", strerror(errno));
  else
    SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_EXEC_FILE "%s: %s", filename, strerror(errno));

  return(return_value);
  }

/*
 * Expects:
 *   filename == argv[0]
 *   username may be NULL
 *   password may be NULL
 *   timestamp may be NULL
 *
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int exec_checkpassword(struct filter_settings *current_settings, char *command_line, char *username, char *password, char *timestamp)
  {
  int return_value;
  int i;
  int j;
  char **child_argv;
  int strlen_command_line;
  char *tmp_command_line;
  int argc;

  return_value = 0;

  if (command_line != NULL)
    {
    child_argv = NULL;

    strlen_command_line = strlen(command_line);
    if ((tmp_command_line = (char *)malloc(sizeof(char) * (strlen_command_line + 1))) != NULL)
      {
      argc = 1;

      for (i = 0; i < strlen_command_line; i++)
        if (command_line[i] == ' ')
          {
          tmp_command_line[i] = '\0';
          argc++;
          }
        else
          tmp_command_line[i] = command_line[i];

      tmp_command_line[i] = '\0';

      if ((child_argv = (char **)malloc(sizeof(char *) * (argc + 1))) != NULL)
        {
        child_argv[0] = tmp_command_line;
        j = 1;
        for (i = 0; i < strlen_command_line; i++)
          if (tmp_command_line[i] == '\0')
            {
            child_argv[j] = tmp_command_line + i + 1;
            j++;
            }

        child_argv[j] = NULL;

        return_value = exec_checkpassword_argv(current_settings, child_argv[0], child_argv, username, password, timestamp);

        free(child_argv);
        }
      else
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char) * (strlen_command_line + 1));

      free(tmp_command_line);
      }
    else
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char) * (strlen_command_line + 1));
    }

  return(return_value);
  }

/*
 * Expects:
 *   filename == argv[0]
 *   size_return_content must contain the size of the preallocated buffer pointed to by *return_content or -1 if *return_content is to be allocated as needed.
 *
 * Return value:
 *   ERROR: -1
 *   SUCCESS: length of returned string
 */
int exec_command_argv(struct filter_settings *current_settings, char *filename, char *argv[], struct expect_send *protocol, char **return_content, int size_return_content, int *return_status)
  {
  int return_value;
  int i;
  int last_match;
  int stdout_pipe[2];
  int stderr_pipe[2];
  int output_pipe[2];
  int stdout_read_result;
  int stderr_read_result;
  pid_t child_pid;
  pid_t wait_pid;
  char input_buf[MAX_COMMAND_BUF + 1];
  int strlen_input_buf;
  int status;
  fd_set read_fds;
  fd_set write_fds;
  int max_fd;
  struct timeval timeout;
  time_t start_time;
  int strlen_input_total;
  char *tmp_ptr;
  char *tmp_alloc;
  char *tmp_return_content;
  int tmp_strlen;
  int current_protocol;
  char new_filename[MAX_BUF + 1];

  return_value = -1;
  tmp_return_content = NULL;

  if ((filename != NULL) &&
      (return_content != NULL))
    {
    if (find_path(current_settings, filename, current_settings->current_environment, new_filename, MAX_BUF))
      if (pipe(output_pipe) != -1)
        if (pipe(stdout_pipe) != -1)
          if (pipe(stderr_pipe) != -1)
            {
            SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_EXEC, argv[0]);

            if ((child_pid = fork()) > 0)
              {
              close(output_pipe[0]);
              close(stdout_pipe[1]);
              close(stderr_pipe[1]);

              return_value = 0;
              strlen_input_buf = 0;
              strlen_input_total = 0;
              current_protocol = 0;
              start_time = time(NULL);

              timeout.tv_sec = TIMEOUT_COMMAND_SECS;
              timeout.tv_usec = 0;

              FD_ZERO(&read_fds);
              FD_ZERO(&write_fds);

              max_fd = -1;
              if ((protocol == NULL) ||
                  (protocol[current_protocol].type == ES_TYPE_EXPECT) ||
                  (protocol[current_protocol].type == ES_TYPE_NONE))
                {
                FD_SET(stdout_pipe[0], &read_fds);
                FD_SET(stderr_pipe[0], &read_fds);
                max_fd = MAXVAL(stdout_pipe[0], stderr_pipe[0]);
                }

              if ((protocol != NULL) &&
                  (protocol[current_protocol].type == ES_TYPE_SEND))
                {
                FD_SET(output_pipe[1], &write_fds);
                max_fd = MAXVAL(max_fd, output_pipe[1]);
                }

              last_match = 0;

              while ((max_fd >= 0) &&
                     (timeout.tv_sec > 0) &&
                     (select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout) >= 0))
                {
                stdout_read_result = -1;
                stderr_read_result = -1;

                if (((stdout_pipe[0] >= 0) &&
                     FD_ISSET(stdout_pipe[0], &read_fds) &&
                     ((stdout_read_result = read(stdout_pipe[0], input_buf + strlen_input_buf, MAX_COMMAND_BUF - strlen_input_buf)) > 0)) ||
                    ((stderr_pipe[0] >= 0) &&
                     FD_ISSET(stderr_pipe[0], &read_fds) &&
                     ((stderr_read_result = read(stderr_pipe[0], input_buf + strlen_input_buf, MAX_COMMAND_BUF - strlen_input_buf)) > 0)))
                  {
                  strlen_input_buf += stdout_read_result + stderr_read_result + 1;
                  strlen_input_total += stdout_read_result + stderr_read_result + 1;
                  input_buf[strlen_input_buf] = '\0';

                  if (strlen_input_buf >= MAX_COMMAND_BUF)
                    {
                    if (size_return_content == -1)
                      if ((tmp_alloc = realloc(tmp_return_content, sizeof(char) * (strlen_input_total + 1))) != NULL)
                        {
                        memcpy(tmp_alloc + (strlen_input_total - strlen_input_buf), input_buf, sizeof(char) * strlen_input_buf);
                        tmp_alloc[strlen_input_total] = '\0';
                        tmp_return_content = tmp_alloc;
                        }
                      else
                        {
                        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char) * (strlen_input_total + 1));
                        return_value = -1;
                        break;
                        }
                    else if ((strlen_input_total - strlen_input_buf) < size_return_content)
                      {
                      tmp_strlen = MINVAL(size_return_content, strlen_input_total);
                      memcpy(*return_content, input_buf, sizeof(char) * tmp_strlen);
                      (*return_content)[tmp_strlen] = '\0';
                      }
                    else
                      break;

                    strlen_input_buf = 0;
                    }
                  }
                else if ((stdout_read_result == 0) &&
                         (stdout_pipe[0] >= 0))
                  {
                  close(stdout_pipe[0]);
                  stdout_pipe[0] = -1;
                  }
                else if ((stderr_read_result == 0) &&
                         (stderr_pipe[0] >= 0))
                  {
                  close(stderr_pipe[0]);
                  stderr_pipe[0] = -1;
                  }

                if ((protocol != NULL) &&
                    (protocol[current_protocol].type == ES_TYPE_EXPECT) &&
                    ((strlen_input_total - last_match) >= protocol[current_protocol].strlen_data))
                  {
                  if (last_match <= (strlen_input_total - strlen_input_buf))
                    {
                    /* Location of the last match is within the return buffer so search both the return buffer and the input buffer */
                    if (((tmp_ptr = strstr(((size_return_content == -1) ? tmp_return_content : (*return_content)) + last_match, protocol[current_protocol].data)) != NULL) ||
                        ((tmp_ptr = strstr(input_buf, protocol[current_protocol].data)) != NULL))
                      {
                      if ((last_match = (tmp_ptr - ((size_return_content == -1) ? tmp_return_content : (*return_content)))) > (strlen_input_total - protocol[current_protocol].strlen_data))
                        last_match = tmp_ptr - input_buf;

                      last_match += protocol[current_protocol].strlen_data;
                      current_protocol++;
                      }
                    else
                      /* Look for data spanning between the return buffer and the input buffer */
                      for (i = 1; i < (protocol[current_protocol].strlen_data - 1); i++)
                        if ((((size_return_content == -1) ? tmp_return_content : (*return_content))[(strlen_input_total - strlen_input_buf) + i - 1] == protocol[current_protocol].data[0]) &&
                            !strncmp(((size_return_content == -1) ? tmp_return_content : (*return_content)) + (strlen_input_total - strlen_input_buf) + i - 1, protocol[current_protocol].data, i) &&
                            !strncmp(input_buf, protocol[current_protocol].data + i, protocol[current_protocol].strlen_data - i))
                          {
                          last_match = ((strlen_input_total - strlen_input_buf) + i - 1) + protocol[current_protocol].strlen_data;
                          current_protocol++;
                          break;
                          }
                    }
                  else if ((tmp_ptr = strstr(input_buf, protocol[current_protocol].data)) != NULL)
                    {
                    last_match = (tmp_ptr - input_buf) + protocol[current_protocol].strlen_data;
                    current_protocol++;
                    }
                  }

                if ((protocol != NULL) &&
                    (protocol[current_protocol].type == ES_TYPE_SEND) &&
                    FD_ISSET(output_pipe[1], &write_fds))
                  {
                  /*
                   * This defeats an "unused result" warning from gcc.
                   * Ignoring this result here is perfectly safe.
                   */
                  i = write(output_pipe[1], protocol[current_protocol].data, protocol[current_protocol].strlen_data);
                  current_protocol++;
                  }

                FD_ZERO(&read_fds);
                FD_ZERO(&write_fds);

                max_fd = -1;

                if ((protocol == NULL) ||
                    (protocol[current_protocol].type == ES_TYPE_EXPECT) ||
                    (protocol[current_protocol].type == ES_TYPE_NONE))
                  {
                  if (stdout_pipe[0] >= 0)
                    {
                    FD_SET(stdout_pipe[0], &read_fds);
                    max_fd = MAXVAL(max_fd, stdout_pipe[0]);
                    }
                  if (stderr_pipe[0] >= 0)
                    {
                    FD_SET(stderr_pipe[0], &read_fds);
                    max_fd = MAXVAL(max_fd, stderr_pipe[0]);
                    }
                  }

                if ((protocol != NULL) &&
                    (protocol[current_protocol].type == ES_TYPE_SEND))
                  {
                  FD_SET(output_pipe[1], &write_fds);
                  max_fd = MAXVAL(max_fd, output_pipe[1]);
                  }

                timeout.tv_sec = TIMEOUT_COMMAND_SECS - (time(NULL) - start_time);
                timeout.tv_usec = 0;
                }

              close(output_pipe[1]);
              if (stdout_pipe[0] != -1)
                close(stdout_pipe[0]);
              if (stderr_pipe[0] != -1)
                close(stderr_pipe[0]);

              do
                {
                if ((wait_pid = waitpid(child_pid, &status, WNOHANG)) == 0)
                  {
                  timeout.tv_sec = 0;
                  timeout.tv_usec = TIMEOUT_COMMAND_EXIT_USECS;
                  select(0, NULL, NULL, NULL, &timeout);
                  }
                }
              while ((wait_pid == 0) &&
                     ((time(NULL) - start_time) < TIMEOUT_COMMAND_SECS));

              if ((wait_pid == child_pid) &&
                  WIFEXITED(status))
                {
                SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_COMMAND_EXIT, WEXITSTATUS(status), new_filename);
                if (return_status != NULL)
                  *return_status = WEXITSTATUS(status);
                }
              else
                {
                kill(child_pid, SIGKILL);
                SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_COMMAND_ABEND "%s", new_filename);
                }

              if (strlen_input_buf > 0)
                {
                if (size_return_content == -1)
                  if ((tmp_alloc = realloc(tmp_return_content, sizeof(char) * (strlen_input_total + 1))) != NULL)
                    {
                    memcpy(tmp_alloc + (strlen_input_total - strlen_input_buf), input_buf, sizeof(char) * strlen_input_buf);
                    tmp_alloc[strlen_input_total] = '\0';
                    tmp_return_content = tmp_alloc;
                    }
                  else
                    {
                    SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char) * (strlen_input_total + 1));
                    return_value = -1;
                    }
                else if ((strlen_input_total - strlen_input_buf) < size_return_content)
                  {
                  tmp_strlen = MINVAL(size_return_content, strlen_input_total);
                  memcpy(*return_content, input_buf, sizeof(char) * tmp_strlen);
                  (*return_content)[tmp_strlen] = '\0';
                  }
                }

              if (size_return_content == -1)
                {
                if (*return_content != NULL)
                  free(*return_content);

                *return_content = tmp_return_content;
                tmp_return_content = NULL;
                return_value = strlen_input_total;
                }
              else
                return_value = MINVAL(size_return_content, strlen_input_total);
              }
            else if (child_pid == 0)
              {
              close(output_pipe[1]);
              close(stdout_pipe[0]);
              close(stderr_pipe[0]);

              current_settings->current_options->log_target = LOG_USE_SYSLOG;

              if (dup2(output_pipe[0], STDIN_FD) != -1)
                if (dup2(stdout_pipe[1], STDOUT_FD) != -1)
                  if (dup2(stderr_pipe[1], STDERR_FD) != -1)
                    {
                    signal(SIGPIPE, SIG_DFL);

                    execve(new_filename, argv, current_settings->current_environment);

                    SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_EXEC "%s: %s", filename, strerror(errno));

                    close(output_pipe[0]);
                    close(stdout_pipe[1]);
                    close(stderr_pipe[1]);

                    exit(0);
                    }
                  else
                    {
                    SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MOVE_DESCRIPTORS "%s", strerror(errno));

                    close(output_pipe[0]);
                    close(stdout_pipe[1]);
                    close(stderr_pipe[1]);
                    }
                else
                  {
                  SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MOVE_DESCRIPTORS "%s", strerror(errno));

                  close(output_pipe[0]);
                  close(stdout_pipe[1]);
                  close(stderr_pipe[1]);
                  }
              else
                {
                SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MOVE_DESCRIPTORS "%s", strerror(errno));

                close(output_pipe[0]);
                close(stdout_pipe[1]);
                close(stderr_pipe[1]);
                }
              }
            else
              {
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_FORK "%s", strerror(errno));

              close(stderr_pipe[0]);
              close(stderr_pipe[1]);
              close(stdout_pipe[0]);
              close(stdout_pipe[1]);
              close(output_pipe[0]);
              close(output_pipe[1]);
              }
            }
          else
            {
            SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_PIPE "%s", strerror(errno));

            close(stdout_pipe[0]);
            close(stdout_pipe[1]);
            close(output_pipe[0]);
            close(output_pipe[1]);
            }
        else
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_PIPE "%s", strerror(errno));

          close(output_pipe[0]);
          close(output_pipe[1]);
          }
      else
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_PIPE "%s", strerror(errno));
    else
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_EXEC_FILE "%s: %s", filename, strerror(errno));
    }

  if (tmp_return_content != NULL)
    free(tmp_return_content);

  return(return_value);
  }

/*
 * Expects:
 *   size_return_content must contain the size of the preallocated buffer pointed to by *return_content or -1 if *return_content is to be allocated as needed.
 *
 * Return value:
 *   ERROR: -1
 *   SUCCESS: length of returned string
 */
int exec_command(struct filter_settings *current_settings, char *command_line, struct expect_send *protocol, char **return_content, int size_return_content, int *return_status)
  {
  int return_value;
  int i;
  int j;
  char **child_argv;
  int strlen_command_line;
  char *tmp_command_line;
  int argc;

  return_value = 0;

  if (command_line != NULL)
    {
    child_argv = NULL;

    strlen_command_line = strlen(command_line);
    if ((tmp_command_line = (char *)malloc(sizeof(char) * (strlen_command_line + 1))) != NULL)
      {
      argc = 1;

      for (i = 0; i < strlen_command_line; i++)
        if (command_line[i] == ' ')
          {
          tmp_command_line[i] = '\0';
          argc++;
          }
        else
          tmp_command_line[i] = command_line[i];

      tmp_command_line[i] = '\0';

      if ((child_argv = (char **)malloc(sizeof(char *) * (argc + 1))) != NULL)
        {
        child_argv[0] = tmp_command_line;
        j = 1;
        for (i = 0; i < strlen_command_line; i++)
          if (tmp_command_line[i] == '\0')
            {
            child_argv[j] = tmp_command_line + i + 1;
            j++;
            }

        child_argv[j] = NULL;

        return_value = exec_command_argv(current_settings, child_argv[0], child_argv, protocol, return_content, size_return_content, return_status);

        free(child_argv);
        }
      else
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char) * (strlen_command_line + 1));

      free(tmp_command_line);
      }
    else
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char) * (strlen_command_line + 1));
    }

  return(return_value);
  }
