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
#include "spamdyke.h"
#include "tls.h"

#ifdef HAVE_LIBSSL

#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <sys/select.h>

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

#include "log.h"
#include "search_fs.h"

/*
 * Return value:
 *   length of returned string
 */
int tls_password_callback(char *buf, int size, int rwflag, void *userdata)
  {
  int return_value;

  return_value = 0;

  if (((struct option_set *)userdata)->strlen_tls_privatekey_password > 0)
    return_value = SNPRINTF(buf, size, "%.*s", ((struct option_set *)userdata)->strlen_tls_privatekey_password, ((struct option_set *)userdata)->tls_privatekey_password);

  return(return_value);
  }

char *tls_error(struct filter_settings *current_settings, int return_code)
  {
  static char error_text[MAX_BUF + 1];
  int strlen_error_text;
  int saved_errno;
  int tls_error;
  int ssl_error;

  saved_errno = errno;
  strlen_error_text = 0;
  error_text[0] = '\0';

  ssl_error = SSL_get_error(current_settings->tls_session, return_code);

  switch (ssl_error)
    {
    case SSL_ERROR_NONE:
      /* No error occurred. */
      strlen_error_text = MINVAL(STRLEN(LOG_MSG_TLS_NO_ERROR), MAX_BUF);
      memcpy(error_text, LOG_MSG_TLS_NO_ERROR, sizeof(char) * strlen_error_text);
      error_text[strlen_error_text] = '\0';

      break;
    case SSL_ERROR_ZERO_RETURN:
      /* SSL connection closed */
      strlen_error_text = MINVAL(STRLEN(LOG_MSG_TLS_ZERO_RETURN), MAX_BUF);
      memcpy(error_text, LOG_MSG_TLS_ZERO_RETURN, sizeof(char) * strlen_error_text);
      error_text[strlen_error_text] = '\0';

      break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* operation did not complete, call it again */
    case SSL_ERROR_WANT_CONNECT:

#ifdef SSL_ERROR_WANT_ACCEPT

    case SSL_ERROR_WANT_ACCEPT:

#endif /* SSL_ERROR_WANT_ACCEPT */

      /* operation did not complete, call it again */
    case SSL_ERROR_WANT_X509_LOOKUP:
      /* callback function wants another callback.  Call the SSL function again. */
      strlen_error_text = MINVAL(STRLEN(LOG_MSG_TLS_RECALL), MAX_BUF);
      memcpy(error_text, LOG_MSG_TLS_RECALL, sizeof(char) * strlen_error_text);
      error_text[strlen_error_text] = '\0';

      break;
    case SSL_ERROR_SYSCALL:
      /* check the SSL error queue.  If return_code == 0, EOF found.  If return_code == -1, check errno. */
      strlen_error_text = MINVAL(STRLEN(LOG_MSG_TLS_SYSCALL), MAX_BUF);
      memcpy(error_text, LOG_MSG_TLS_SYSCALL, sizeof(char) * strlen_error_text);
      error_text[strlen_error_text] = '\0';

      if (return_code == 0)
        {
        snprintf(error_text + strlen_error_text, MAX_BUF - strlen_error_text, ", %s", LOG_MSG_TLS_EOF_FOUND);
        strlen_error_text += strlen(error_text + strlen_error_text);
        }
      else if (return_code == -1)
        {
        snprintf(error_text + strlen_error_text, MAX_BUF - strlen_error_text, ", %s", strerror(saved_errno));
        strlen_error_text += strlen(error_text + strlen_error_text);
        }

      break;
    case SSL_ERROR_SSL:
      /* Library failure, check the SSL error queue. */
      strlen_error_text = MINVAL(STRLEN(LOG_MSG_TLS_LIBRARY), MAX_BUF);
      memcpy(error_text, LOG_MSG_TLS_LIBRARY, sizeof(char) * strlen_error_text);
      error_text[strlen_error_text] = '\0';

      break;
    default:
      strlen_error_text = MINVAL(STRLEN(LOG_MISSING_DATA), MAX_BUF);
      memcpy(error_text, LOG_MISSING_DATA, sizeof(char) * strlen_error_text);
      error_text[strlen_error_text] = '\0';

      break;
    }

  while (((tls_error = ERR_get_error()) != 0) &&
         (strlen_error_text < MAX_BUF))
    {
    if (strlen_error_text > 0)
      {
      snprintf(error_text + strlen_error_text, MAX_BUF - strlen_error_text, ", ");
      strlen_error_text += strlen(error_text + strlen_error_text);
      }

    ERR_error_string_n(tls_error, error_text + strlen_error_text, MAX_BUF - strlen_error_text);
    strlen_error_text += strlen(error_text + strlen_error_text);
    }

  return(error_text);
  }

/*
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int tls_init_inner(struct filter_settings *current_settings, SSL_CTX **target_tls_context, SSL **target_tls_session)
  {
  static int initialized = 0;
  int return_value;
  int i;
  int tmp_rand;
  int error_occurred;
  int tls_return;
  FILE *tmp_file;
  DH *tmp_dh;

  return_value = 0;

  if (!initialized)
    {
    SSL_library_init();

    if (!RAND_status())
      {
      srand(time(NULL));

      i = 0;
      do
        {
        tmp_rand = rand();
        RAND_seed(&tmp_rand, sizeof(int));
        i++;
        }
      while (!RAND_status() &&
             (i < MAX_RAND_SEED));

      if (i < MAX_RAND_SEED)
        initialized = 1;
      else
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_INIT, NULL);
      }
    else
      initialized = 1;
    }

  if (initialized)
    {
    if ((*target_tls_context = SSL_CTX_new(SSLv23_server_method())) != NULL)
      {
      error_occurred = 0;

      if ((current_settings->current_options->strlen_tls_privatekey_password == 0) &&
          (current_settings->current_options->tls_privatekey_password_file != NULL))
        current_settings->current_options->strlen_tls_privatekey_password = read_file_first_line(current_settings, current_settings->current_options->tls_privatekey_password_file, &current_settings->current_options->tls_privatekey_password);

      if (current_settings->current_options->strlen_tls_privatekey_password > 0)
        {
        SSL_CTX_set_default_passwd_cb(*target_tls_context, &tls_password_callback);
        SSL_CTX_set_default_passwd_cb_userdata(*target_tls_context, (void *)current_settings->current_options);
        }

      if (current_settings->current_options->tls_certificate_file != NULL)
        {
        if ((tls_return = SSL_CTX_use_certificate_chain_file(*target_tls_context, current_settings->current_options->tls_certificate_file)) == 1)
          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_CERTIFICATE, current_settings->current_options->tls_certificate_file);
        else
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_CERTIFICATE "%s : %s", current_settings->current_options->tls_certificate_file, tls_error(current_settings, tls_return));
          error_occurred = 1;
          }
        }

      if (!error_occurred &&
          (current_settings->current_options->tls_privatekey_file != NULL))
        {
        if ((tls_return = SSL_CTX_use_PrivateKey_file(*target_tls_context, current_settings->current_options->tls_privatekey_file, SSL_FILETYPE_PEM)) == 1)
          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_PRIVATEKEY_SEPARATE, current_settings->current_options->tls_privatekey_file);
        else
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_PRIVATEKEY "%s : %s", current_settings->current_options->tls_privatekey_file, tls_error(current_settings, tls_return));
          error_occurred = 1;
          }
        }
      else if (!error_occurred &&
               (current_settings->current_options->tls_certificate_file != NULL))
        {
        if ((tls_return = SSL_CTX_use_PrivateKey_file(*target_tls_context, current_settings->current_options->tls_certificate_file, SSL_FILETYPE_PEM)) == 1)
          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_PRIVATEKEY_CERTIFICATE, current_settings->current_options->tls_certificate_file);
        else
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_PRIVATEKEY "%s : %s", current_settings->current_options->tls_certificate_file, tls_error(current_settings, tls_return));
          error_occurred = 1;
          }
        }

      if (!error_occurred)
        {
        if (SSL_CTX_check_private_key(*target_tls_context))
          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_CERT_CHECK, NULL);
        else
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_CERT_CHECK "%s : %s", (current_settings->current_options->tls_privatekey_file != NULL) ? current_settings->current_options->tls_privatekey_file : current_settings->current_options->tls_certificate_file, tls_error(current_settings, 0));
          error_occurred = 1;
          }
        }

      if (!error_occurred &&
          (current_settings->current_options->tls_dhparams_file != NULL))
        {
        if ((SSL_CTX_set_options(*target_tls_context, SSL_OP_SINGLE_DH_USE) & SSL_OP_SINGLE_DH_USE) == SSL_OP_SINGLE_DH_USE)
          {
          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_OPTIONS, "SSL_OP_SINGLE_DH_USE");

          if ((tmp_file = fopen(current_settings->current_options->tls_dhparams_file, "r")) != NULL)
            {
            if ((tmp_dh = PEM_read_DHparams(tmp_file, NULL, NULL, NULL)) != NULL)
              {
              SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_DHPARAMS, current_settings->current_options->tls_dhparams_file);

              if ((tls_return = SSL_CTX_set_tmp_dh(*target_tls_context, tmp_dh)) == 1)
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_SET_DHPARAMS, NULL);
              else
                {
                SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_SET_DHPARAMS ": %s", tls_error(current_settings, tls_return));
                error_occurred = 1;
                }
              }
            else
              {
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_DHPARAMS "%s", current_settings->current_options->tls_dhparams_file);
              error_occurred = 1;
              }

            fclose(tmp_file);
            }
          else
            {
            SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_OPEN "%s: %s", current_settings->current_options->tls_dhparams_file, strerror(errno));
            error_occurred = 1;
            }
          }
        else
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_OPTIONS "SSL_OP_SINGLE_DH_USE", NULL);
          error_occurred = 1;
          }
        }

      if (!error_occurred)
        {
        if ((tls_return = SSL_CTX_set_cipher_list(*target_tls_context, current_settings->current_options->tls_cipher_list)) == 1)
          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_CIPHER_LIST, current_settings->current_options->tls_cipher_list);
        else
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_CIPHER_LIST "%s: %s", current_settings->current_options->tls_cipher_list, tls_error(current_settings, tls_return));
          error_occurred = 1;
          }
        }

      if (!error_occurred &&
          ((*target_tls_session = SSL_new(*target_tls_context)) != NULL))
        return_value = 1;
      else
        {
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_INIT, NULL);

        SSL_CTX_free(*target_tls_context);
        *target_tls_context = NULL;
        }
      }
    else
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_INIT, NULL);
    }

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int tls_init(struct filter_settings *current_settings)
  {
  return(tls_init_inner(current_settings, &current_settings->tls_context, &current_settings->tls_session));
  }

/*
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int tls_start(struct filter_settings *current_settings, int read_fd, int write_fd)
  {
  int return_value;
  int tls_return;
  int continue_looping;
  struct timeval tmp_timeval;
  int socket_state;

  return_value = 0;

  if ((current_settings->tls_session != NULL) &&
      SSL_set_rfd(current_settings->tls_session, read_fd) &&
      SSL_set_wfd(current_settings->tls_session, write_fd))
    {
    /*
     * Set input and output sockets to non-blocking
     * to prevent hangs inside OpenSSL.
     */
    if ((socket_state = fcntl(read_fd, F_GETFL, 0)) != -1)
      {
      if ((socket_state & O_NONBLOCK) != O_NONBLOCK)
        {
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_SOCKET_NONBLOCK, read_fd);
        if (fcntl(read_fd, F_SETFL, socket_state | O_NONBLOCK) == -1)
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_NONBLOCK_INPUT "%s", strerror(errno));
        }
      }
    else
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_STATUS_INPUT "%s", strerror(errno));

    if ((socket_state = fcntl(write_fd, F_GETFL, 0)) != -1)
      {
      if ((socket_state & O_NONBLOCK) != O_NONBLOCK)
        {
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_SOCKET_NONBLOCK, write_fd);
        if (fcntl(write_fd, F_SETFL, socket_state | O_NONBLOCK) == -1)
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_NONBLOCK_OUTPUT "%s", strerror(errno));
        }
      }
    else
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_STATUS_OUTPUT "%s", strerror(errno));

    continue_looping = 1;
    tls_return = 1;

    while (continue_looping &&
           ((current_settings->current_options->timeout_command == 0) ||
            ((time(NULL) - current_settings->command_start) < current_settings->current_options->timeout_command)) &&
           ((current_settings->current_options->timeout_connection == 0) ||
            ((time(NULL) - current_settings->connection_start) < current_settings->current_options->timeout_connection)))
      if ((tls_return = SSL_accept(current_settings->tls_session)) == 1)
        {
        SSL_set_mode(current_settings->tls_session, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_set_mode(current_settings->tls_session, SSL_MODE_AUTO_RETRY);
        current_settings->tls_state = TLS_STATE_ACTIVE_SPAMDYKE;

        SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_TLS_CIPHER, SSL_CIPHER_get_name(SSL_get_current_cipher(current_settings->tls_session)), SSL_CIPHER_get_bits(SSL_get_current_cipher(current_settings->tls_session), NULL));

        return_value = 1;
        break;
        }
      else
        switch (SSL_get_error(current_settings->tls_session, tls_return))
          {
          case SSL_ERROR_WANT_READ:
          case SSL_ERROR_WANT_WRITE:

#ifdef SSL_ERROR_WANT_ACCEPT

          case SSL_ERROR_WANT_ACCEPT:

#endif /* SSL_ERROR_WANT_ACCEPT */

          case SSL_ERROR_WANT_CONNECT:
          case SSL_ERROR_WANT_X509_LOOKUP:
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_DELAY, time(NULL) - current_settings->command_start);

            tmp_timeval.tv_sec = MIN_SELECT_SECS_TIMEOUT;
            tmp_timeval.tv_usec = MIN_SELECT_USECS_TIMEOUT;
            select(0, NULL, NULL, NULL, &tmp_timeval);
            break;
          default:
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_TLS_ACCEPT ": %s", tls_error(current_settings, tls_return));
            continue_looping = 0;

            break;
          }

    if (continue_looping &&
        (return_value == 0))
      SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_TLS_ACCEPT ": %s", tls_error(current_settings, tls_return));
    }
  else
    SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_TLS_INIT, NULL);

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int tls_end_inner(struct filter_settings *current_settings, int read_fd, SSL_CTX **target_tls_context, SSL **target_tls_session)
  {
  int return_value;
  struct timeval tmp_timeval;
  int continue_looping;
  int tls_return;

  return_value = 0;

  if (current_settings->tls_state == TLS_STATE_ACTIVE_SPAMDYKE)
    {
    /* The socket is going to be closed, so proper SSL shutdown isn't a big
       deal.  We'll give it a chance to happen though. */
    continue_looping = 1;

    while (continue_looping &&
           ((time(NULL) - current_settings->command_start) < TIMEOUT_TLS_SHUTDOWN_SECS) &&
           ((current_settings->current_options->timeout_command == 0) ||
            ((time(NULL) - current_settings->command_start) < current_settings->current_options->timeout_command)) &&
           ((current_settings->current_options->timeout_connection == 0) ||
            ((time(NULL) - current_settings->connection_start) < current_settings->current_options->timeout_connection)))
      if ((tls_return = SSL_shutdown(*target_tls_session)) == 1)
        break;
      else
        switch (SSL_get_error(current_settings->tls_session, tls_return))
          {
          case SSL_ERROR_WANT_READ:
          case SSL_ERROR_WANT_WRITE:

#ifdef SSL_ERROR_WANT_ACCEPT

          case SSL_ERROR_WANT_ACCEPT:

#endif /* SSL_ERROR_WANT_ACCEPT */

          case SSL_ERROR_WANT_CONNECT:
          case SSL_ERROR_WANT_X509_LOOKUP:
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_DELAY, time(NULL) - current_settings->command_start);

            tmp_timeval.tv_sec = MIN_SELECT_SECS_TIMEOUT;
            tmp_timeval.tv_usec = MIN_SELECT_USECS_TIMEOUT;
            select(0, NULL, NULL, NULL, &tmp_timeval);
            break;
          default:
            /* Didn't work.  Oh well. */
            continue_looping = 0;
            break;
          }

    current_settings->tls_state = TLS_STATE_INACTIVE;
    return_value = 1;
    }

  if (*target_tls_session != NULL)
    {
    /* NOTE: SSL_free() may not actually free the SSL object if the reference
       count is above zero.  There's no way to tell if it did, however. */
    SSL_free(*target_tls_session);
    *target_tls_session = NULL;
    }

  if (*target_tls_session != NULL)
    {
    /* NOTE: SSL_CTX_free() may not actually free the SSL object if the
       reference count is above zero.  There's no way to tell if it did,
       however. */
    SSL_CTX_free(*target_tls_context);
    *target_tls_context = NULL;
    }

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int tls_end(struct filter_settings *current_settings, int read_fd)
  {
  return(tls_end_inner(current_settings, read_fd, &current_settings->tls_context, &current_settings->tls_session));
  }

/*
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int tls_test(struct filter_settings *current_settings)
  {
  int return_value;
  SSL_CTX *tmp_context;
  SSL *tmp_session;

  tmp_context = NULL;
  tmp_session = NULL;

  return_value = tls_init_inner(current_settings, &tmp_context, &tmp_session);
  tls_end_inner(current_settings, -1, &tmp_context, &tmp_session);

  return(return_value);
  }

/*
 * Return value:
 *   NO DATA: 0
 *   DATA WAITING: 1
 */
int tls_can_read(struct filter_settings *current_settings)
  {
  return((current_settings->tls_state == TLS_STATE_ACTIVE_SPAMDYKE) ? SSL_pending(current_settings->tls_session) : 0);
  }

/*
 * Return value:
 *   number of bytes read or 0 for EOF
 */
ssize_t tls_read(struct filter_settings *current_settings, int target_fd, void *target_buf, size_t num_bytes)
  {
  ssize_t return_value;
  int continue_looping;
  struct timeval tmp_timeval;

  if (current_settings->tls_state == TLS_STATE_ACTIVE_SPAMDYKE)
    {
    continue_looping = 1;
    return_value = 0;

    while (continue_looping &&
           ((current_settings->current_options->timeout_command == 0) ||
            ((time(NULL) - current_settings->command_start) < current_settings->current_options->timeout_command)) &&
           ((current_settings->current_options->timeout_connection == 0) ||
            ((time(NULL) - current_settings->connection_start) < current_settings->current_options->timeout_connection)))
      if ((return_value = SSL_read(current_settings->tls_session, target_buf, num_bytes)) > 0)
        break;
      else
        switch (SSL_get_error(current_settings->tls_session, return_value))
          {
          case SSL_ERROR_WANT_READ:
          case SSL_ERROR_WANT_WRITE:

#ifdef SSL_ERROR_WANT_ACCEPT

          case SSL_ERROR_WANT_ACCEPT:

#endif /* SSL_ERROR_WANT_ACCEPT */

          case SSL_ERROR_WANT_CONNECT:
          case SSL_ERROR_WANT_X509_LOOKUP:
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_DELAY, time(NULL) - current_settings->command_start);

            tmp_timeval.tv_sec = MIN_SELECT_SECS_TIMEOUT;
            tmp_timeval.tv_usec = MIN_SELECT_USECS_TIMEOUT;
            select(0, NULL, NULL, NULL, &tmp_timeval);
            break;
          default:
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_TLS_READ ": %s", tls_error(current_settings, return_value));
            continue_looping = 0;
            break;
          }

    if (continue_looping &&
        (return_value <= 0))
      SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_TLS_READ ": %s", tls_error(current_settings, return_value));
    }
  else
    return_value = read(target_fd, target_buf, num_bytes);

  return(return_value);
  }

/*
 * Return value:
 *   number of bytes written
 */
ssize_t tls_write(struct filter_settings *current_settings, int target_fd, void *target_buf, size_t num_bytes)
  {
  ssize_t return_value;
  int continue_looping;
  struct timeval tmp_timeval;

  if (current_settings->tls_state == TLS_STATE_ACTIVE_SPAMDYKE)
    {
    continue_looping = 1;
    return_value = 0;

    while (continue_looping &&
           ((current_settings->current_options->timeout_command == 0) ||
            ((time(NULL) - current_settings->command_start) < current_settings->current_options->timeout_command)) &&
           ((current_settings->current_options->timeout_connection == 0) ||
            ((time(NULL) - current_settings->connection_start) < current_settings->current_options->timeout_connection)))
      if ((return_value = SSL_write(current_settings->tls_session, target_buf, num_bytes)) > 0)
        break;
      else
        switch (SSL_get_error(current_settings->tls_session, return_value))
          {
          case SSL_ERROR_WANT_READ:
          case SSL_ERROR_WANT_WRITE:

#ifdef SSL_ERROR_WANT_ACCEPT

          case SSL_ERROR_WANT_ACCEPT:

#endif /* SSL_ERROR_WANT_ACCEPT */

          case SSL_ERROR_WANT_CONNECT:
          case SSL_ERROR_WANT_X509_LOOKUP:
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_TLS_DELAY, time(NULL) - current_settings->command_start);

            tmp_timeval.tv_sec = MIN_SELECT_SECS_TIMEOUT;
            tmp_timeval.tv_usec = MIN_SELECT_USECS_TIMEOUT;
            select(0, NULL, NULL, NULL, &tmp_timeval);
            break;
          default:
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_TLS_WRITE ": %s", tls_error(current_settings, return_value));
            continue_looping = 0;
            break;
          }

    if (continue_looping &&
        (return_value <= 0))
      SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_TLS_WRITE ": %s", tls_error(current_settings, return_value));
    }
  else
    return_value = write(target_fd, target_buf, num_bytes);

  return(return_value);
  }

#endif /* HAVE_LIBSSL */

char *tls_state_desc(struct filter_settings *current_settings)
  {
  char *return_value;

  return_value = TLS_DESC_UNKNOWN;

  switch (current_settings->tls_state)
    {
    case TLS_STATE_ACTIVE_SPAMDYKE:
      switch (current_settings->current_options->tls_level)
        {
        case TLS_LEVEL_PROTOCOL:
        case TLS_LEVEL_PROTOCOL_SPAMDYKE:
          return_value = TLS_DESC_SPAMDYKE_PROTOCOL;
          break;
        case TLS_LEVEL_SMTPS:
          return_value = TLS_DESC_SPAMDYKE_SMTPS;
          break;
        }

      break;
    case TLS_STATE_ACTIVE_PASSTHROUGH:
      return_value = TLS_DESC_PASSTHROUGH;
      break;
    case TLS_STATE_INACTIVE:
      return_value = TLS_DESC_INACTIVE;
      break;
    }

  return(return_value);
  }
