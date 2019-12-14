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
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <sys/select.h>
#include <stdlib.h>

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

#include "spamdyke-qrv.h"
#include "exec-qrv.h"
#include "log-qrv.h"

/*
 * Expects:
 *   filename == argv[0]
 *   size_return_content must contain the size of the preallocated buffer pointed to by return_content
 *
 * Return value:
 *   ERROR: -1
 *   SUCCESS: length of returned string
 */
int exec_command_argv(struct qrv_settings *current_settings, char *filename, char *argv[], char *return_content, int size_return_content, int *return_status, int target_uid, int target_gid)
  {
  int return_value;
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
  int tmp_strlen;
  uid_t tmp_uid;
  gid_t tmp_gid;

  return_value = -1;

  if ((filename != NULL) &&
      (return_content != NULL))
    {
    if (pipe(output_pipe) != -1)
      if (pipe(stdout_pipe) != -1)
        if (pipe(stderr_pipe) != -1)
          {
          tmp_uid = (target_uid == 0) ? -1 : target_uid;
          tmp_gid = (target_gid == 0) ? -1 : target_gid;
          QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_EXEC, tmp_uid, tmp_gid, filename);

          if ((child_pid = fork()) > 0)
            {
            close(output_pipe[0]);
            close(stdout_pipe[1]);
            close(stderr_pipe[1]);

            return_value = 0;
            strlen_input_buf = 0;
            strlen_input_total = 0;
            start_time = time(NULL);

            timeout.tv_sec = TIMEOUT_COMMAND_SECS;
            timeout.tv_usec = 0;

            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);

            max_fd = -1;
            FD_SET(stdout_pipe[0], &read_fds);
            FD_SET(stderr_pipe[0], &read_fds);
            max_fd = MAXVAL(stdout_pipe[0], stderr_pipe[0]);

            while ((max_fd >= 0) &&
                   (timeout.tv_sec > 0) &&
                   (select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout) >= 0))
              {
              stdout_read_result = -1;
              stderr_read_result = -1;

              if (((stdout_pipe[0] >= 0) &&
                   FD_ISSET(stdout_pipe[0], &read_fds) &&
                   ((stdout_read_result = read(stdout_pipe[0], input_buf + strlen_input_buf, MAX_BUF - strlen_input_buf)) > 0)) ||
                  ((stderr_pipe[0] >= 0) &&
                   FD_ISSET(stderr_pipe[0], &read_fds) &&
                   ((stderr_read_result = read(stderr_pipe[0], input_buf + strlen_input_buf, MAX_BUF - strlen_input_buf)) > 0)))
                {
                strlen_input_buf += stdout_read_result + stderr_read_result + 1;
                strlen_input_total += stdout_read_result + stderr_read_result + 1;
                input_buf[strlen_input_buf] = '\0';
                QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CHILD_OUTPUT, strlen_input_buf, input_buf);

                if (strlen_input_buf >= MAX_COMMAND_BUF)
                  {
                  if ((strlen_input_total - strlen_input_buf) < size_return_content)
                    {
                    tmp_strlen = MINVAL(size_return_content, strlen_input_total);
                    memcpy(return_content, input_buf, sizeof(char) * tmp_strlen);
                    return_content[tmp_strlen] = '\0';
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

              FD_ZERO(&read_fds);
              FD_ZERO(&write_fds);

              max_fd = -1;

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
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_COMMAND_EXIT, WEXITSTATUS(status), filename);
              if (return_status != NULL)
                *return_status = WEXITSTATUS(status);
              }
            else
              {
              kill(child_pid, SIGKILL);
              QRV_LOG_ERROR(current_settings, LOG_ERROR_COMMAND_ABEND, filename);
              }

            if ((strlen_input_buf > 0) &&
                ((strlen_input_total - strlen_input_buf) < size_return_content))
              {
              tmp_strlen = MINVAL(size_return_content, strlen_input_total);
              memcpy(return_content, input_buf, sizeof(char) * tmp_strlen);
              return_content[tmp_strlen] = '\0';
              }

            return_value = MINVAL(size_return_content, strlen_input_total);
            }
          else if (child_pid == 0)
            {
            close(output_pipe[1]);
            close(stdout_pipe[0]);
            close(stderr_pipe[0]);

            if (dup2(output_pipe[0], STDIN_FD) != -1)
              if (dup2(stdout_pipe[1], STDOUT_FD) != -1)
                if (dup2(stderr_pipe[1], STDERR_FD) != -1)
                  {
                  signal(SIGPIPE, SIG_DFL);

                  setgid(tmp_gid);
                  setuid(tmp_uid);

                  execve(filename, argv, current_settings->environment);

                  QRV_LOG_ERROR(current_settings, LOG_ERROR_EXEC, filename, strerror(errno));

                  close(output_pipe[0]);
                  close(stdout_pipe[1]);
                  close(stderr_pipe[1]);

                  exit(-1);
                  }
                else
                  {
                  QRV_LOG_ERROR(current_settings, LOG_ERROR_MOVE_DESCRIPTORS, strerror(errno));

                  close(output_pipe[0]);
                  close(stdout_pipe[1]);
                  close(stderr_pipe[1]);
                  }
              else
                {
                QRV_LOG_ERROR(current_settings, LOG_ERROR_MOVE_DESCRIPTORS, strerror(errno));

                close(output_pipe[0]);
                close(stdout_pipe[1]);
                close(stderr_pipe[1]);
                }
            else
              {
              QRV_LOG_ERROR(current_settings, LOG_ERROR_MOVE_DESCRIPTORS, strerror(errno));

              close(output_pipe[0]);
              close(stdout_pipe[1]);
              close(stderr_pipe[1]);
              }
            }
          else
            {
            QRV_LOG_ERROR(current_settings, LOG_ERROR_FORK, strerror(errno));

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
          QRV_LOG_ERROR(current_settings, LOG_ERROR_PIPE, strerror(errno));

          close(stdout_pipe[0]);
          close(stdout_pipe[1]);
          close(output_pipe[0]);
          close(output_pipe[1]);
          }
      else
        {
        QRV_LOG_ERROR(current_settings, LOG_ERROR_PIPE, strerror(errno));

        close(output_pipe[0]);
        close(output_pipe[1]);
        }
    else
      QRV_LOG_ERROR(current_settings, LOG_ERROR_PIPE, strerror(errno));
    }

  return(return_value);
  }
