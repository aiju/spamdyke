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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <strings.h>
#include <fcntl.h>

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
#include "search_fs.h"
#include "environment.h"
#include "configuration.h"
#include "dns.h"

/*
 * The DNS packet format is not well documented outside of the RFCs.  There is
 * almost no sample or tutorial code to be found on the internet outside of the
 * sendmail source code, which is pretty hard to read.
 *
 * Basically, each DNS packet starts with a HEADER structure, defined in
 * arpa/nameser.h (or arpa/nameser_compat.h on Linux).  Most of the time, the
 * header can be skipped.
 *
 * After the header, the nameserver returns all of the "questions" it was asked,
 * so the answers will make sense.  If you're asking more than one "question"
 * per query, this is important.  Otherwise, skip them by finding the size of
 * each question with dn_skipname() and advancing past them.  The number of
 * questions is found in the qdcount field of the header.
 *
 * Next is the answer section, which can contain many answers, though multiple
 * answers may not make much sense for all query types.  The number of answers
 * is found in the ancount field of the header.  Within each answer, the first
 * field is the name that was queried, for reference.  It can be skipped with
 * dn_skipname().
 *
 * After that comes the type in a 16 bit field, then the class in a 16 bit
 * field, then the time-to-live (TTL) in a 32 bit field, then the answer size
 * in a 16 bit field.  The type and size are important; the class and the ttl
 * can usually be ignored.  The format of the rest of the answer field is
 * different depending on the type.
 *
 * IF THE TYPE IS A:
 * The first 4 bytes are the four octets of the IP address.
 *
 * IF THE TYPE IS TXT:
 * The first 8 bits are an unsigned integer indicating the total length of
 * the text response.  The following bytes are the ASCII text of the response.
 *
 * IF THE TYPE IS PTR OR NS:
 * All of the bytes are the compressed name of the result.  They can be
 * decoded with dn_expand().
 *
 * IF THE TYPE IS CNAME:
 * All of the bytes are the compressed name of the CNAME entry.  They can be
 * decoded with dn_expand().
 *
 * IF THE TYPE IS MX:
 * Each answer begins with an unsigned 16 bit integer indicating the preference
 * of the mail server (lower preferences should be contacted first).  The
 * remainder of the answer is the mail server name.  It can be decoded with
 * dn_expand().
 *
 * IF THE TYPE IS SOA:
 * The first section of bytes are the compressed name of the primary NS server.
 * They can be decoded with dn_expand().  The second section of bytes are the
 * compressed name of the administrator's mailbox.  They can be decoded with
 * dn_expand().  After the end of the mailbox data, five 32 bit integers give
 * the serial number, the refresh interval, the retry interval, the expiration
 * limit and the minimum time to live, in that order.
 *
 * SEE ALSO:
 *   RFC 1035
 *   http://www.zytrax.com/books/dns/ch15/
 *   "DNS and BIND" from O'Reilly
 */
char *nihdns_type_name(int target_type)
  {
  char *return_value;

  switch (target_type)
    {
    case NIHDNS_TYPE_A:
      return_value = LOG_MESSAGE_DNS_TYPE_A;
      break;
    case NIHDNS_TYPE_CNAME:
      return_value = LOG_MESSAGE_DNS_TYPE_CNAME;
      break;
    case NIHDNS_TYPE_MX:
      return_value = LOG_MESSAGE_DNS_TYPE_MX;
      break;
    case NIHDNS_TYPE_NS:
      return_value = LOG_MESSAGE_DNS_TYPE_NS;
      break;
    case NIHDNS_TYPE_PTR:
      return_value = LOG_MESSAGE_DNS_TYPE_PTR;
      break;
    case NIHDNS_TYPE_SOA:
      return_value = LOG_MESSAGE_DNS_TYPE_SOA;
      break;
    case NIHDNS_TYPE_TXT:
      return_value = LOG_MESSAGE_DNS_TYPE_TXT;
      break;
    default:
      return_value = LOG_MISSING_DATA;
      break;
    }

  return(return_value);
  }

/*
 * The return value must only be used to skip bytes in the DNS packet, not used
 * as the length of the string in return_buf.  That string will be null-
 * terminated, but the length will be returned in strlen_return_buf.  Because
 * of DNS packet compression, the two values may be very different.
 *
 * Return value:
 *   ERROR: -1
 *   SUCCESS: number of bytes to skip
 */
int nihdns_expand(struct filter_settings *current_settings, char *answer_start, char *answer_end, char *answer_ptr, char *return_buf, int length_return_buf, int *strlen_return_buf)
  {
  int return_value;
  char *tmp_ptr;
  int return_len;
  int found_pointer;

  return_value = 0;
  return_len = 0;
  found_pointer = 0;

  if ((answer_start != NULL) &&
      (answer_end != NULL) &&
      (answer_end > answer_start) &&
      (answer_ptr != NULL) &&
      (return_buf != NULL) &&
      (length_return_buf > 0))
    {
    tmp_ptr = answer_ptr;
    while ((tmp_ptr >= answer_start) &&
           (tmp_ptr < answer_end) &&
           (return_value < length_return_buf))
      if ((tmp_ptr[0] & 0xC0) == 0xC0)
        {
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_EXPAND_POINTER, tmp_ptr - answer_ptr, NIHDNS_GETINT16(tmp_ptr) & 0x3FFF);
        if (((tmp_ptr = answer_start + (NIHDNS_GETINT16(tmp_ptr) & 0x3FFF)) <= answer_end) &&
            (tmp_ptr > answer_start))
          {
          return_value += 2;
          found_pointer = 1;
          }
        else
          {
          return_value = -1;
          break;
          }
        }
      else if (tmp_ptr[0] > 0)
        {
        if (return_len > 0)
          {
          return_buf[return_len] = '.';
          return_len++;
          }

        memcpy(return_buf + return_len, tmp_ptr + 1, MINVAL(tmp_ptr[0], length_return_buf - return_len));
        return_len += MINVAL(tmp_ptr[0], length_return_buf - return_len);
        return_buf[return_len] = '\0';
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_EXPAND_STRING, tmp_ptr - answer_ptr, tmp_ptr[0], return_len);

        if (!found_pointer)
          return_value += tmp_ptr[0] + 1;

        if (((tmp_ptr += tmp_ptr[0] + 1) > answer_end) ||
            (tmp_ptr < answer_start))
          {
          return_value = -1;
          break;
          }
        }
      else
        {
        if (!found_pointer)
          return_value++;

        break;
        }
    }

  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_EXPAND_RESULT, return_len, return_value, return_buf);

  if ((return_value != -1) &&
      (strlen_return_buf != NULL))
    *strlen_return_buf = return_len;

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: -1
 *   SUCCESS: number of bytes to skip
 */
int nihdns_skip(char *answer_ptr, char *answer_end)
  {
  int error_occurred;
  char *tmp_ptr;

  error_occurred = 0;
  tmp_ptr = answer_ptr;

  if ((answer_ptr != NULL) &&
      (answer_end != NULL) &&
      (answer_ptr < answer_end))
    {
    while (tmp_ptr < answer_end)
      if ((tmp_ptr[0] & 0xC0) == 0xC0)
        {
        if ((tmp_ptr += 2) > answer_end)
          error_occurred = 1;

        break;
        }
      else if (tmp_ptr[0] > 0)
        {
        if (((tmp_ptr += tmp_ptr[0] + 1) > answer_end) ||
            (tmp_ptr < answer_ptr))
          {
          error_occurred = 1;
          break;
          }
        }
      else
        {
        tmp_ptr++;
        break;
        }
    }

  return(!error_occurred ? (tmp_ptr - answer_ptr) : -1);
  }

void nihdns_empty_udp_buffer(int udp_socket)
  {
  fd_set read_fds;
  int select_result;
  char tmp_buf[MAX_DNS_PACKET_BYTES_UDP];
  struct timeval tmp_timeval;

  if (udp_socket >= 0)
    {
    select_result = 0;

    do
      {
      if (select_result > 0)
        recvfrom(udp_socket, tmp_buf, MAX_DNS_PACKET_BYTES_UDP, 0, NULL, NULL);

      FD_ZERO(&read_fds);
      FD_SET(udp_socket, &read_fds);
      tmp_timeval.tv_sec = 0;
      tmp_timeval.tv_usec = 0;
      }
    while ((select_result = select(udp_socket + 1, &read_fds, NULL, NULL, &tmp_timeval)) > 0);
    }

  return;
  }

/*
 * RETURN VALUE: total number of servers successfully parsed
 */
int nihdns_parse_servers(struct filter_settings *current_settings, int default_port)
  {
  int i;
  int num_primary_servers;
  int num_secondary_servers;
  char ip_octets[4][4];
  char port[6];
  int target_ip_ints[4];
  int target_port;
  int scan_result;
  char tmp_ip[MAX_BUF + 1];

  num_primary_servers = 0;
  if (current_settings->current_options->nihdns_primary_server_list != NULL)
    for (i = 0; (i < MAX_NIHDNS_SERVERS) && (current_settings->current_options->nihdns_primary_server_list[i] != NULL); i++)
      {
      target_port = 0;
      if (((scan_result = sscanf(current_settings->current_options->nihdns_primary_server_list[i], "%3[0-9].%3[0-9].%3[0-9].%3[0-9]%*[.:]%5[0-9]", ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3], port)) >= 4) &&
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
          (target_ip_ints[3] <= 255) &&
          ((scan_result == 4) ||
           (sscanf(port, "%d", &target_port) == 1)))
        {
        if ((scan_result > 4) &&
            ((target_port <= 0) ||
             (target_port > 65535)))
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_NS_PORT_BAD, default_port, current_settings->current_options->nihdns_primary_server_list[i]);
          target_port = 0;
          }

        snprintf(tmp_ip, MAX_BUF, "%d.%d.%d.%d", target_ip_ints[0], target_ip_ints[1], target_ip_ints[2], target_ip_ints[3]);
        if (inet_aton(tmp_ip, &current_settings->current_options->nihdns_primary_server_data[i].sin_addr))
          {
          current_settings->current_options->nihdns_primary_server_data[num_primary_servers].sin_family = AF_INET;
          current_settings->current_options->nihdns_primary_server_data[num_primary_servers].sin_port = (target_port != 0) ? htons(target_port) : htons(default_port);
          num_primary_servers++;
          current_settings->current_options->nihdns_primary_server_data[num_primary_servers].sin_addr.s_addr = INADDR_ANY;

          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_NS, tmp_ip, (target_port != 0) ? target_port : default_port);
          }
        else
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_NS_BAD, current_settings->current_options->nihdns_primary_server_list[i]);
        }
      else
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_NS_BAD, current_settings->current_options->nihdns_primary_server_list[i]);
      }

  num_secondary_servers = 0;
  if (current_settings->current_options->nihdns_secondary_server_list != NULL)
    for (i = 0; (i < MAX_NIHDNS_SERVERS) && (current_settings->current_options->nihdns_secondary_server_list[i] != NULL); i++)
      {
      target_port = 0;
      if (((scan_result = sscanf(current_settings->current_options->nihdns_secondary_server_list[i], "%3[0-9].%3[0-9].%3[0-9].%3[0-9]%*[.:]%5[0-9]", ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3], port)) >= 4) &&
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
          (target_ip_ints[3] <= 255) &&
          ((scan_result == 4) ||
           (sscanf(port, "%d", &target_port) == 1)))
        {
        if ((scan_result > 4) &&
            ((target_port <= 0) ||
             (target_port > 65535)))
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_NS_PORT_BAD, default_port, current_settings->current_options->nihdns_secondary_server_list[i]);
          target_port = 0;
          }

        snprintf(tmp_ip, MAX_BUF, "%d.%d.%d.%d", target_ip_ints[0], target_ip_ints[1], target_ip_ints[2], target_ip_ints[3]);
        if (inet_aton(tmp_ip, &current_settings->current_options->nihdns_secondary_server_data[i].sin_addr))
          {
          current_settings->current_options->nihdns_secondary_server_data[num_secondary_servers].sin_family = AF_INET;
          current_settings->current_options->nihdns_secondary_server_data[num_secondary_servers].sin_port = (target_port != 0) ? htons(target_port) : htons(default_port);
          num_secondary_servers++;
          current_settings->current_options->nihdns_secondary_server_data[num_secondary_servers].sin_addr.s_addr = INADDR_ANY;

          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_NS, tmp_ip, (target_port != 0) ? target_port : default_port);
          }
        else
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_NS_BAD, current_settings->current_options->nihdns_secondary_server_list[i]);
        }
      else
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_NS_BAD, current_settings->current_options->nihdns_secondary_server_list[i]);
      }

  return(num_primary_servers + num_secondary_servers);
  }

int nihdns_initialize(struct filter_settings *current_settings, int close_socket)
  {
  static int udp_socket = -1;
  int i;
  char *resolv_env;
  char timeout[6];
  int target_timeout;
  struct sockaddr_in tmp_sockaddr;
  int max_buf_socket = MAX_BUF_SOCKET;
  int default_port;
  int strlen_tmp_ip;
  char tmp_ip[MAX_BUF + 1];

  if (!close_socket)
    {
    if ((current_settings->current_options->nihdns_primary_server_data[0].sin_addr.s_addr == INADDR_ANY) &&
        (current_settings->current_options->nihdns_secondary_server_data[0].sin_addr.s_addr == INADDR_ANY))
      {
      default_port = DEFAULT_NIHDNS_PORT;

      if (current_settings->current_options->nihdns_level > NIHDNS_LEVEL_NONE)
        {
        if (nihdns_parse_servers(current_settings, default_port) == 0)
          {
          free_string_array(&current_settings->current_options->nihdns_primary_server_list, current_settings->base_options.nihdns_primary_server_list);
          free_string_array(&current_settings->current_options->nihdns_secondary_server_list, current_settings->base_options.nihdns_secondary_server_list);

          if (current_settings->current_options->nihdns_resolv_conf != NULL)
            for (i = 0; current_settings->current_options->nihdns_resolv_conf[i] != NULL; i++)
              {
              load_resolver_file(current_settings, current_settings->current_options->nihdns_resolv_conf[i], &default_port);
              print_configuration(current_settings);
              }

          if (nihdns_parse_servers(current_settings, default_port) == 0)
            {
            free_string_array(&current_settings->current_options->nihdns_primary_server_list, current_settings->base_options.nihdns_primary_server_list);
            free_string_array(&current_settings->current_options->nihdns_secondary_server_list, current_settings->base_options.nihdns_secondary_server_list);

            strlen_tmp_ip = SNPRINTF(tmp_ip, MAX_BUF, "%s:%d", LOCALHOST_IP, default_port);
            append_string(current_settings, &current_settings->current_options->nihdns_primary_server_list, tmp_ip, strlen_tmp_ip);

            current_settings->current_options->nihdns_primary_server_data[0].sin_family = AF_INET;
            current_settings->current_options->nihdns_primary_server_data[0].sin_port = htons(default_port);
            current_settings->current_options->nihdns_primary_server_data[0].sin_addr.s_addr = ntohl(INADDR_LOOPBACK);

            current_settings->current_options->nihdns_primary_server_data[1].sin_addr.s_addr = INADDR_ANY;

            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_NS_LOOPBACK, inet_ntoa(current_settings->current_options->nihdns_primary_server_data[0].sin_addr), default_port);
            print_configuration(current_settings);
            }
          }
        }
      }

    if (udp_socket == -1)
      {
      if ((current_settings->current_options->nihdns_primary_server_data[0].sin_addr.s_addr != INADDR_ANY) ||
          (current_settings->current_options->nihdns_secondary_server_data[0].sin_addr.s_addr != INADDR_ANY))
        {
        if ((resolv_env = find_environment_variable(current_settings, current_settings->current_environment, ENVIRONMENT_RESOLV_OPTION, STRLEN(ENVIRONMENT_RESOLV_OPTION), NULL)) != NULL)
          while (resolv_env[0] != '\0')
            {
            for (; (resolv_env[0] != '\0') && isspace((int)resolv_env[0]); resolv_env++);

            if (!strncmp(resolv_env, NIHDNS_RESOLV_OPTION_TIMEOUT, STRLEN(NIHDNS_RESOLV_OPTION_TIMEOUT)))
              {
              resolv_env += STRLEN(NIHDNS_RESOLV_OPTION_TIMEOUT);
              target_timeout = 0;
              if ((sscanf(resolv_env, "%5[0-9]", timeout) == 1) &&
                  (sscanf(timeout, "%d", &target_timeout) == 1) &&
                  (target_timeout > 0) &&
                  (target_timeout <= 65536))
                {
                current_settings->current_options->nihdns_timeout_total_secs_system = target_timeout * current_settings->current_options->nihdns_attempts_total;

                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_RESOLV_QUERY_TIMEOUT_ENV, ENVIRONMENT_RESOLV_OPTION, target_timeout);
                }
              else
                SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_RESOLV_QUERY_TIMEOUT_BAD_ENV, ENVIRONMENT_RESOLV_OPTION, resolv_env);
              }

            for (; (resolv_env[0] != '\0') && !isspace((int)resolv_env[0]); resolv_env++);
            }

        tmp_sockaddr.sin_family = AF_INET;
        tmp_sockaddr.sin_port = 0;
        tmp_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        bzero(&tmp_sockaddr.sin_zero, 8);

        if ((udp_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) != -1)
          {
          if (fcntl(udp_socket, F_SETFL, fcntl(udp_socket, F_GETFL, 0) | O_NONBLOCK) == -1)
            SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_NONBLOCK_DNS_UDP "%s", strerror(errno));

          if (bind(udp_socket, (struct sockaddr *)&tmp_sockaddr, sizeof(struct sockaddr)) == 0)
            {
            if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVBUF, (char *)&max_buf_socket, sizeof(int)) != 0)
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SETSOCKOPT, strerror(errno));

            if (setsockopt(udp_socket, SOL_SOCKET, SO_SNDBUF, (char *)&max_buf_socket, sizeof(int)) != 0)
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SETSOCKOPT, strerror(errno));
            }
          else
            {
            SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_BIND, strerror(errno));
            close(udp_socket);
            udp_socket = -1;
            }
          }
        else
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SOCKET_UDP, strerror(errno));
        }
      }
    }
  else if (udp_socket != -1)
    {
    nihdns_empty_udp_buffer(udp_socket);
    close(udp_socket);
    udp_socket = -1;
    }

  return(udp_socket);
  }

/*
 * Return value:
 *   ERROR: -1
 *   SUCCESS: fd of socket
 */
int nihdns_create_socket_tcp(struct filter_settings *current_settings)
  {
  int return_value;

  return_value = -1;

  if ((return_value = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
    if (fcntl(return_value, F_SETFL, fcntl(return_value, F_GETFL, 0) | O_NONBLOCK) == -1)
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_NONBLOCK_DNS_TCP "%s", strerror(errno));
    }
  else
    SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SOCKET_TCP, strerror(errno));

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: -1
 *   SUCCESS: size of packet
 */
int nihdns_create_packet(struct filter_settings *current_settings, int id, char *target_name, int type, char *return_query, int length_return_query)
  {
  static char packet_template[] = { /* ID */ 0x00, 0x00,
                                    /* QR, OPCODE, AA, TC, RD, RA, RCODE */ 0x01, 0x00,
                                    /* QDCOUNT */ 0x00, 0x00,
                                    /* ANCOUNT */ 0x00, 0x00,
                                    /* NSCOUNT */ 0x00, 0x00,
                                    /* ARCOUNT */ 0x00, 0x00 };
  int return_value;
  int i;
  int strlen_target_name;
  uint16_t tmp_num;
  char *tmp_ptr;
  char *last_ptr;

  return_value = -1;

  if (target_name != NULL)
    {
    strlen_target_name = strlen(target_name);
    while ((strlen_target_name > 0) &&
           (target_name[strlen_target_name - 1] == '.'))
      strlen_target_name--;
    }
  else
    strlen_target_name = 0;

  if (strlen_target_name > 0)
    {
    if (length_return_query > (sizeof(packet_template) + strlen_target_name + 10))
      {
      memcpy(return_query, packet_template, sizeof(packet_template));

      tmp_num = id;
      return_query[0] = ((char *)&tmp_num)[0];
      return_query[1] = ((char *)&tmp_num)[1];

      tmp_num = htons(1L);
      return_query[4] = ((char *)&tmp_num)[0];
      return_query[5] = ((char *)&tmp_num)[1];

      last_ptr = return_query + sizeof(packet_template);
      tmp_ptr = return_query + sizeof(packet_template) + 1;

      for (i = 0; i < strlen_target_name; i++)
        if (target_name[i] != '.')
          {
          tmp_ptr[0] = target_name[i];
          tmp_ptr++;
          }
        else
          {
          last_ptr[0] = (tmp_ptr - last_ptr) - 1;
          last_ptr = tmp_ptr;
          tmp_ptr++;
          }

      last_ptr[0] = (tmp_ptr - last_ptr) - 1;
      tmp_ptr[0] = 0x00;
      tmp_ptr++;

      tmp_num = htons(type);
      tmp_ptr[0] = ((char *)&tmp_num)[0];
      tmp_ptr[1] = ((char *)&tmp_num)[1];
      tmp_ptr += 2;

      tmp_num = htons(NIHDNS_CLASS_INTERNET);
      tmp_ptr[0] = ((char *)&tmp_num)[0];
      tmp_ptr[1] = ((char *)&tmp_num)[1];
      tmp_ptr += 2;

      return_value = tmp_ptr - return_query;
      }
    else
      SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_OVERSIZE_QUERY, length_return_query, target_name, nihdns_type_name(type));
    }

  return(return_value);
  }

/*
 * Expects:
 *   target_name_array must contain FQDNs, not relational names
 *   return_answer must not be NULL
 *
 * Return value:
 *   ERROR (no response): -1
 *   NO RESULT (negative query): 0
 *   FOUND RESULT: length of answer
*/
int nihdns_query(struct filter_settings *current_settings, char **target_name_array, int type_array, int preferred_type, char *return_answer, int return_answer_length, char **return_answer_start, int *return_target_name_index)
  {
  static unsigned short query_id = 0;
  static int config_type_array[] = CONFIG_DNS_TYPE_ARRAY;
  static int nihdns_type_array[] = NIHDNS_TYPE_ARRAY;
  int return_value;
  int i;
  int j;
  int k;
  int num_names;
  int active_types;
  int udp_socket;
  char *question;
  char *answer;
  char packet_buf[MAX_DNS_PACKET_BYTES_UDP + 2];
  char *answer_ptr;
  char *answer_start;
  char **tcp_buf;
  int *tcp_buf_strlen;
  int *tcp_answer_len;
  int num_questions;
  int size;
  int num_answers;
  int type;
  int *question_length;
  int *socket_list;
  unsigned short tmp_num;
  unsigned short response_id;
  unsigned short start_id;
  int sendto_result;
  int select_result;
  int response_length;
  fd_set read_fds;
  fd_set write_fds;
  struct timeval tmp_timeval;
  time_t start_time;
  int num_queries;
  int error_occurred;
  int num_primary;
  int num_secondary;
  int num_packets_sent;
  struct sockaddr_in *target_server;
  int max_socket;
  struct sockaddr_in server_address;
  socklen_t server_address_len;
  int num_types;
  int types[NUM_NIHDNS_TYPE];
  int current_timeout_total_secs;
  char *potential_return_answer;
  char *potential_return_answer_start;
  int potential_return_target_name_index;
  int potential_return_value;
  int target_type;

  return_value = -1;
  error_occurred = 0;
  num_names = 0;
  udp_socket = 0;

  question = NULL;
  question_length = NULL;
  socket_list = NULL;
  tcp_buf = NULL;
  tcp_buf_strlen = NULL;
  tcp_answer_len = NULL;
  potential_return_answer = NULL;
  potential_return_answer_start = NULL;
  potential_return_target_name_index = -1;
  potential_return_value = -1;
  target_type = 0;

  if (query_id == 0)
    query_id = (int)random();

  num_types = 0;
  for (i = 0; i < NUM_NIHDNS_TYPE; i++)
    if ((type_array & config_type_array[i]) == config_type_array[i])
      {
      types[num_types] = nihdns_type_array[i];
      num_types++;

      if (preferred_type == nihdns_type_array[i])
        {
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_PREFERRED_TYPE, nihdns_type_name(preferred_type));
        target_type = preferred_type;
        }
      }

  if ((num_types > 0) &&
      ((udp_socket = nihdns_initialize(current_settings, 0)) != -1))
    {
    nihdns_empty_udp_buffer(udp_socket);

    for (num_names = 0; target_name_array[num_names] != NULL; num_names++);

    if ((question = (char *)malloc(sizeof(char) * MAX_DNS_PACKET_BYTES_UDP * num_names * num_types)) != NULL)
      {
      if ((question_length = (int *)malloc(sizeof(int) * num_names * num_types)) != NULL)
        {
        if ((socket_list = (int *)malloc(sizeof(int) * num_names * num_types)) != NULL)
          {
          for (i = 0; i < (num_names * num_types); i++)
            socket_list[i] = -1;

          if ((tcp_buf = (char **)malloc(sizeof(char *) * num_names * num_types)) != NULL)
            {
            for (i = 0; i < (num_names * num_types); i++)
              tcp_buf[i] = NULL;

            if ((tcp_buf_strlen = (int *)malloc(sizeof(int) * num_names * num_types)) != NULL)
              {
              for (i = 0; i < (num_names * num_types); i++)
                tcp_buf_strlen[i] = 0;

              if ((tcp_answer_len = (int *)malloc(sizeof(int) * num_names * num_types)) != NULL)
                {
                for (i = 0; i < (num_names * num_types); i++)
                  tcp_answer_len[i] = 0;

                if ((target_type != 0) &&
                    ((potential_return_answer = (char *)malloc(sizeof(char) * return_answer_length)) == NULL))
                  {
                  SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char) * return_answer_length));
                  error_occurred = 1;
                  }
                }
              else
                {
                SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(int) * num_names * num_types));
                error_occurred = 1;
                }
              }
            else
              {
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(int) * num_names * num_types));
              error_occurred = 1;
              }
            }
          else
            {
            SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char *) * num_names * num_types));
            error_occurred = 1;
            }
          }
        else
          {
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(int) * num_names * num_types));
          error_occurred = 1;
          }
        }
      else
        {
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(int) * num_names * num_types));
        error_occurred = 1;
        }
      }
    else
      {
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char) * MAX_DNS_PACKET_BYTES_UDP * num_names * num_types));
      error_occurred = 1;
      }

    if (!error_occurred)
      {
      active_types = num_types * num_names;
      start_id = query_id;

      for (j = 0; j < num_names; j++)
        for (i = 0; i < num_types; i++)
          {
          socket_list[(j * num_types) + i] = udp_socket;
          if ((question_length[(j * num_types) + i] = nihdns_create_packet(current_settings, query_id, target_name_array[j], types[i], question + (((j * num_types) + i) * MAX_DNS_PACKET_BYTES_UDP), MAX_DNS_PACKET_BYTES_UDP)) > 0)
            query_id++;
          }

      start_time = time(NULL);
      num_queries = 0;
      num_primary = -1;
      num_secondary = -1;
      current_timeout_total_secs = (current_settings->current_options->nihdns_timeout_total_secs_parameter != -1) ? current_settings->current_options->nihdns_timeout_total_secs_parameter : ((current_settings->current_options->nihdns_timeout_total_secs_system != -1) ? current_settings->current_options->nihdns_timeout_total_secs_system : DEFAULT_TIMEOUT_NIHDNS_TOTAL_SECS);

      do
        {
        sendto_result = 0;
        num_packets_sent = 0;

        switch (current_settings->current_options->nihdns_level)
          {
          case NIHDNS_LEVEL_NORMAL:
            /*
             * The server_data arrays are terminated by
             * .sin_addr.s_addr == INADDR_ANY
             */
            if (num_primary == -1)
              for (num_primary = 0; current_settings->current_options->nihdns_primary_server_data[num_primary].sin_addr.s_addr != INADDR_ANY; num_primary++);
            if (num_secondary == -1)
              for (num_secondary = 0; current_settings->current_options->nihdns_secondary_server_data[num_secondary].sin_addr.s_addr != INADDR_ANY; num_secondary++);

            while (num_packets_sent == 0)
              {
              error_occurred = 0;

              if ((num_queries < current_settings->current_options->nihdns_attempts_primary) &&
                  (current_settings->current_options->nihdns_primary_server_data[0].sin_addr.s_addr != INADDR_ANY))
                {
                i = num_queries % num_primary;
                target_server = &current_settings->current_options->nihdns_primary_server_data[i];
                }
              else
                {
                i = num_queries % (num_primary + num_secondary);
                target_server = (i < num_primary) ? &current_settings->current_options->nihdns_primary_server_data[i] : &current_settings->current_options->nihdns_secondary_server_data[i - num_primary];
                }

              /*
               * Send one packet to one server for each name
               */
              for (k = 0; (k < num_names) && !error_occurred && (num_packets_sent == 0); k++)
                for (j = 0; j < num_types; j++)
                  if (socket_list[(k * num_types) + j] == udp_socket)
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_QUERY, question_length[(k * num_types) + j], question[((k * num_types) + j) * MAX_DNS_PACKET_BYTES_UDP], question[(((k * num_types) + j) * MAX_DNS_PACKET_BYTES_UDP) + 1], target_name_array[k], nihdns_type_name(types[j]), inet_ntoa(target_server->sin_addr), ntohs(target_server->sin_port), num_queries + 1);
                    if ((sendto_result = sendto(udp_socket, question + (((k * num_types) + j) * MAX_DNS_PACKET_BYTES_UDP), question_length[(k * num_types) + j], 0, (struct sockaddr *)target_server, sizeof(struct sockaddr))) == -1)
                      {
                      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SENDTO, question_length[(k * num_types) + j], strerror(errno));
                      error_occurred = 1;
                      num_packets_sent = 0;
                      break;
                      }
                    else if (sendto_result != question_length[(k * num_types) + j])
                      {
                      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SENDTO_INCOMPLETE, question_length[(k * num_types) + j], sendto_result);
                      error_occurred = 1;
                      num_packets_sent = 0;
                      break;
                      }
                    else
                      num_packets_sent++;
                    }

              i++;
              if (i < (num_primary + num_secondary))
                i = 0;
              if (i == (num_queries % (num_primary + num_secondary)))
                break;
              }

            break;
          case NIHDNS_LEVEL_AGGRESSIVE:
            /*
             * The server_data arrays are terminated by
             * .sin_addr.s_addr == INADDR_ANY
             */
            for (i = 0; current_settings->current_options->nihdns_primary_server_data[i].sin_addr.s_addr != INADDR_ANY; i++)
              {
              /*
               * Send packets to each server for each name
               */
              error_occurred = 0;
              for (k = 0; (k < num_names) && !error_occurred; k++)
                for (j = 0; j < num_types; j++)
                  if (socket_list[(k * num_types) + j] == udp_socket)
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_QUERY, question_length[(k * num_types) + j], question[((k * num_types) + j) * MAX_DNS_PACKET_BYTES_UDP], question[(((k * num_types) + j) * MAX_DNS_PACKET_BYTES_UDP) + 1], target_name_array[k], nihdns_type_name(types[j]), inet_ntoa(current_settings->current_options->nihdns_primary_server_data[i].sin_addr), ntohs(current_settings->current_options->nihdns_primary_server_data[i].sin_port), num_queries + 1);
                    if ((sendto_result = sendto(udp_socket, question + (((k * num_types) + j) * MAX_DNS_PACKET_BYTES_UDP), question_length[(k * num_types) + j], 0, (struct sockaddr *)&current_settings->current_options->nihdns_primary_server_data[i], sizeof(struct sockaddr))) == -1)
                      {
                      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SENDTO, question_length[(k * num_types) + j], strerror(errno));
                      error_occurred = 1;
                      break;
                      }
                    else if (sendto_result != question_length[(k * num_types) + j])
                      {
                      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SENDTO_INCOMPLETE, question_length[(k * num_types) + j], sendto_result);
                      error_occurred = 1;
                      break;
                      }
                    else
                      num_packets_sent++;
                    }
              }

            /*
             * The server_data arrays are terminated by
             * .sin_addr.s_addr == INADDR_ANY
             */
            if ((num_queries >= current_settings->current_options->nihdns_attempts_primary) ||
                (current_settings->current_options->nihdns_primary_server_data[0].sin_addr.s_addr == INADDR_ANY))
              for (i = 0; current_settings->current_options->nihdns_secondary_server_data[i].sin_addr.s_addr != INADDR_ANY; i++)
                {
                error_occurred = 0;
                for (k = 0; (k < num_names) && !error_occurred; k++)
                  for (j = 0; j < num_types; j++)
                    if (socket_list[(k * num_types) + j] == udp_socket)
                      {
                      SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_QUERY, question_length[(k * num_types) + j], question[((k * num_types) + j) * MAX_DNS_PACKET_BYTES_UDP], question[(((k * num_types) + j) * MAX_DNS_PACKET_BYTES_UDP) + 1], target_name_array[k], nihdns_type_name(types[j]), inet_ntoa(current_settings->current_options->nihdns_secondary_server_data[i].sin_addr), ntohs(current_settings->current_options->nihdns_secondary_server_data[i].sin_port), num_queries + 1);
                      if ((sendto_result = sendto(udp_socket, question + (((k * num_types) + j) * MAX_DNS_PACKET_BYTES_UDP), question_length[(k * num_types) + j], 0, (struct sockaddr *)&current_settings->current_options->nihdns_secondary_server_data[i], sizeof(struct sockaddr))) == -1)
                        {
                        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SENDTO, question_length[(k * num_types) + j], strerror(errno));
                        error_occurred = 1;
                        break;
                        }
                      else if (sendto_result != question_length[(k * num_types) + j])
                        {
                        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SENDTO_INCOMPLETE, question_length[(k * num_types) + j], sendto_result);
                        error_occurred = 1;
                        break;
                        }
                      else
                        num_packets_sent++;
                      }
                }

            break;
          }

        num_queries++;

        if (num_packets_sent > 0)
          {
          tmp_timeval.tv_sec = MINVAL(current_timeout_total_secs - (time(NULL) - start_time), current_timeout_total_secs / current_settings->current_options->nihdns_attempts_total);
          tmp_timeval.tv_usec = 0;
          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_TIMEOUT, tmp_timeval.tv_sec);

          while (!error_occurred &&
                 (tmp_timeval.tv_sec > 0))
            {
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            FD_SET(udp_socket, &read_fds);

            max_socket = udp_socket;
            for (i = 0; i < (num_names * num_types); i++)
              if ((socket_list[i] != -1) &&
                  (socket_list[i] != udp_socket))
                {
                if (tcp_answer_len[i] == -1)
                  FD_SET(socket_list[i], &write_fds);
                else
                  FD_SET(socket_list[i], &read_fds);

                max_socket = MAXVAL(max_socket, socket_list[i]);
                }

            if ((select_result = select(max_socket + 1, &read_fds, &write_fds, NULL, &tmp_timeval)) > 0)
              {
              response_length = 0;
              answer = NULL;

              if (FD_ISSET(udp_socket, &read_fds))
                {
                server_address_len = sizeof(struct sockaddr_in);
                response_length = recvfrom(udp_socket, packet_buf, MAX_DNS_PACKET_BYTES_UDP, 0, (struct sockaddr *)&server_address, &server_address_len);
                answer = packet_buf;

                /*
                 * Safety check to prevent DNS spoofing: compare server_address to
                 * our DNS servers according to the value of nihdns_spoof.
                 */
                if (current_settings->current_options->nihdns_spoof != NIHDNS_SPOOF_ACCEPT_ALL)
                  {
                  for (i = 0; current_settings->current_options->nihdns_primary_server_data[i].sin_addr.s_addr != INADDR_ANY; i++)
                    if (((current_settings->current_options->nihdns_spoof == NIHDNS_SPOOF_ACCEPT_SAME_PORT) ||
                         (current_settings->current_options->nihdns_primary_server_data[i].sin_addr.s_addr == server_address.sin_addr.s_addr)) &&
                        ((current_settings->current_options->nihdns_spoof == NIHDNS_SPOOF_ACCEPT_SAME_IP) ||
                         (current_settings->current_options->nihdns_primary_server_data[i].sin_port == server_address.sin_port)))
                      break;

                  if (current_settings->current_options->nihdns_primary_server_data[i].sin_addr.s_addr == INADDR_ANY)
                    for (i = 0; current_settings->current_options->nihdns_secondary_server_data[i].sin_addr.s_addr != INADDR_ANY; i++)
                      if (((current_settings->current_options->nihdns_spoof == NIHDNS_SPOOF_ACCEPT_SAME_PORT) ||
                           (current_settings->current_options->nihdns_secondary_server_data[i].sin_addr.s_addr == server_address.sin_addr.s_addr)) &&
                          ((current_settings->current_options->nihdns_spoof == NIHDNS_SPOOF_ACCEPT_SAME_IP) ||
                           (current_settings->current_options->nihdns_secondary_server_data[i].sin_port == server_address.sin_port)))
                        break;

                  if (current_settings->current_options->nihdns_secondary_server_data[i].sin_addr.s_addr == INADDR_ANY)
                    {
                    SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_UDP_SPOOF, inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));
                    response_length = 0;
                    }
                  }
                }
              else
                for (i = 0; i < (num_types * num_names); i++)
                  if ((socket_list[i] != -1) &&
                      (socket_list[i] != udp_socket))
                    {
                    if (FD_ISSET(socket_list[i], &read_fds) &&
                        (tcp_answer_len[i] == 0))
                      {
                      if ((tcp_buf[i] != NULL) ||
                          ((tcp_buf[i] = (char *)malloc(sizeof(char) * MAX_DNS_PACKET_BYTES_TCP)) != NULL))
                        {
                        /*
                         * When DNS responses are sent via TCP, the first two bytes
                         * of the response are the length of the entire response
                         * (not including the two additional bytes themselves),
                         * which may be sent in many packets.  So it may take
                         * several read()s to accumulate the entire thing.
                         * tcp_answer_len[i] stores the total length from the first
                         * packet, tcp_buf_strlen[i] stores the number of bytes
                         * received so far.
                         */
                        if ((response_length = read(socket_list[i], tcp_buf[i] + tcp_buf_strlen[i], MAX_DNS_PACKET_BYTES_TCP - tcp_buf_strlen[i])) > 0)
                          {
                          tcp_buf_strlen[i] += response_length;
                          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_RECEIVED_TCP, response_length, tcp_buf_strlen[i], tcp_answer_len[i]);
                          if (tcp_buf_strlen[i] >= 2)
                            {
                            if (tcp_answer_len[i] == 0)
                              {
                              ((char *)&tmp_num)[0] = tcp_buf[i][0];
                              ((char *)&tmp_num)[1] = tcp_buf[i][1];
                              tcp_answer_len[i] = ntohs(tmp_num) + 2;
                              }

                            if (tcp_buf_strlen[i] == tcp_answer_len[i])
                              {
                              answer = tcp_buf[i] + 2;
                              response_length = tcp_answer_len[i] - 2;
                              }
                            else if (tcp_answer_len[i] > MAX_DNS_PACKET_BYTES_TCP)
                              {
                              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_OVERSIZE, target_name_array[i % num_names], tcp_answer_len[i], MAX_DNS_PACKET_BYTES_TCP);
                              close(socket_list[i]);
                              socket_list[i] = -1;
                              }
                            else
                              response_length = 0;
                            }
                          }
                        }
                      else
                        {
                        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char) * MAX_DNS_PACKET_BYTES_TCP));
                        error_occurred = 1;
                        }

                      break;
                      }
                    else if (FD_ISSET(socket_list[i], &write_fds) &&
                             (tcp_answer_len[i] == -1))
                      {
                      SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_QUERY_TCP, question_length[i], question[i * MAX_DNS_PACKET_BYTES_UDP], question[(i * MAX_DNS_PACKET_BYTES_UDP) + 1], target_name_array[i % num_names], nihdns_type_name(types[i / num_names]));

                      memcpy(packet_buf + 2, question + (i * MAX_DNS_PACKET_BYTES_UDP), question_length[i]);
                      tmp_num = htons(question_length[i]);
                      packet_buf[0] = ((char *)&tmp_num)[0];
                      packet_buf[1] = ((char *)&tmp_num)[1];

                      if (write(socket_list[i], packet_buf, question_length[i] + 2) != -1)
                        tcp_answer_len[i] = 0;
                      else
                        {
                        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_WRITE "%s", question_length[i] + 2, socket_list[i], strerror(errno));
                        close(socket_list[i]);
                        socket_list[i] = -1;
                        }

                      break;
                      }
                    }

              if (response_length > 0)
                {
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_RECEIVED, response_length, answer[0], answer[1]);

                ((char *)&tmp_num)[0] = answer[0];
                ((char *)&tmp_num)[1] = answer[1];
                response_id = tmp_num;

                if ((response_id >= start_id) &&
                    (response_id < ((num_names * num_types) + start_id)) &&
                    (socket_list[response_id - start_id] != -1))
                  {
                  response_id -= start_id;

                  /*
                   * Examine the DNS packet header to see if the response is
                   * truncated
                   */
                  if (((answer[2] & 0x02) != 0x02) ||
                      (current_settings->current_options->nihdns_tcp == NIHDNS_TCP_NONE))
                    {
                    /* Skip the header */
                    answer_ptr = answer + sizeof(struct nihdns_header);

                    /* Skip the questions */
                    num_questions = ntohs((unsigned short)((struct nihdns_header *)answer)->qdcount);
                    num_answers = ntohs((unsigned short)((struct nihdns_header *)answer)->ancount);
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_COUNTS, answer[0], answer[1], num_questions, num_answers);

                    if (num_answers > 0)
                      {
                      for (i = 0; i < num_questions; i++)
                        if ((size = nihdns_skip(answer_ptr, answer + response_length)) >= 0)
                          answer_ptr += size + sizeof(uint16_t) + sizeof(uint16_t);
                        else
                          break;

                      if (i == num_questions)
                        {
                        answer_start = answer_ptr;
                        for (i = 0; i < num_answers; i++)
                          if ((size = nihdns_skip(answer_ptr, answer + response_length)) >= 0)
                            {
                            answer_ptr += size;
                            type = NIHDNS_GETINT16(answer_ptr);
                            answer_ptr += sizeof(uint16_t);

                            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_RECEIVED_TYPE, nihdns_type_name(type), nihdns_type_name(types[response_id % num_types]));
                            if (type == types[response_id % num_types])
                              {
                              /*
                               * If the caller asked for a specific "preferred" type and it hasn't been received,
                               * hold this answer for now, just in case the "preferred" type arrives.  If it doesn't
                               * arrive before the next packets are due to be sent, we'll just go with what we have.
                               * Otherwise, any answer will do.
                               */
                              if ((target_type != 0) &&
                                  (type != target_type))
                                {
                                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_POTENTIAL_ANSWER, nihdns_type_name(type), nihdns_type_name(target_type));

                                memcpy(potential_return_answer, answer, MINVAL(response_length, return_answer_length));
                                potential_return_answer_start = potential_return_answer + (answer_start - answer);
                                potential_return_target_name_index = response_id / num_types;

                                potential_return_value = MINVAL(response_length, return_answer_length);
                                }
                              else
                                {
                                memcpy(return_answer, answer, MINVAL(response_length, return_answer_length));
                                if (return_answer_start != NULL)
                                  *return_answer_start = return_answer + (answer_start - answer);
                                if (return_target_name_index != NULL)
                                  *return_target_name_index = response_id / num_types;

                                return_value = MINVAL(response_length, return_answer_length);

                                break;
                                }
                              }
                            }
                        }
                      }
                    else
                      {
                      /*
                       * The response contained no answers, which means "not found".
                       * Setting the socket_list element to -1 will prevent
                       * requerying this name/type combo
                       */
                      if ((socket_list[response_id] != -1) &&
                          (socket_list[response_id] != udp_socket))
                        close(socket_list[response_id]);

                      socket_list[response_id] = -1;
                      active_types--;
                      }
                    }
                  else
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_TRUNCATED, answer[0], answer[1]);
                    if ((socket_list[response_id] = nihdns_create_socket_tcp(current_settings)) != -1)
                      {
                      SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_CONNECT, inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));
                      if ((connect(socket_list[response_id], (struct sockaddr *)&server_address, server_address_len) != -1) ||
                          (errno == EINPROGRESS))
                        tcp_answer_len[response_id] = -1;
                      else
                        {
                        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_CONNECT "%s", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port), strerror(errno));
                        close(socket_list[response_id]);
                        socket_list[response_id] = -1;
                        }
                      }
                    }

                  if (active_types == 0)
                    {
                    for (i = 0; i < num_names; i++)
                      SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_NEGATIVE, target_name_array[i]);

                    return_value = 0;
                    break;
                    }

                  if (return_value >= 0)
                    break;
                  }
                }

              if (return_value >= 0)
                break;

              tmp_timeval.tv_sec = MINVAL(current_timeout_total_secs - (time(NULL) - start_time), current_timeout_total_secs / current_settings->current_options->nihdns_attempts_total);
              tmp_timeval.tv_usec = 0;
              }
            else
              break;
            }

          if (return_value >= 0)
            break;
          else if (potential_return_value >= 0)
            {
            memcpy(return_answer, potential_return_answer, potential_return_value);
            if (return_answer_start != NULL)
              *return_answer_start = return_answer + (potential_return_answer_start - potential_return_answer);
            if (return_target_name_index != NULL)
              *return_target_name_index = potential_return_target_name_index;

            return_value = potential_return_value;

            break;
            }
          }
        else
          break;
        }
      while (!error_occurred &&
             (num_queries < current_settings->current_options->nihdns_attempts_total));
      }
    }

  if (question != NULL)
    free(question);
  if (question_length != NULL)
    free(question_length);
  if (socket_list != NULL)
    {
    for (i = 0; i < (num_names * num_types); i++)
      if ((socket_list[i] != -1) &&
          (socket_list[i] != udp_socket))
        close(socket_list[i]);

    free(socket_list);
    }
  if (tcp_buf != NULL)
    {
    for (i = 0; i < (num_names * num_types); i++)
      if (tcp_buf[i] != NULL)
        free(tcp_buf[i]);

    free(tcp_buf);
    }
  if (tcp_buf_strlen != NULL)
    free(tcp_buf_strlen);
  if (tcp_answer_len != NULL)
    free(tcp_answer_len);
  if (potential_return_answer != NULL)
    free(potential_return_answer);

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: -1
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int nihdns_rbl(struct filter_settings *current_settings, char **target_name_array, char *target_message_buf, int size_target_message_buf, char **target_rbl_array, int *return_target_name_index, struct previous_action *history)
  {
  int return_value;
  int i;
  int j;
  char answer[MAX_DNS_PACKET_BYTES_UDP];
  char host[MAX_HOSTNAME + 1];
  char *answer_ptr;
  char *cname_ptr[MAX_DNS_QUERIES - 1];
  int num_cnames;
  int answer_length;
  int size;
  int txt_length;
  int type;
  int num_answers;
  int num_queries;
  int exit_loop;
  int target_name_index;
  int strlen_name;
  struct previous_action current_lookup;
  struct previous_action *tmp_lookup;
  char **cname_array;
  union
    {
    char *char_ptr;
    struct nihdns_header *header_ptr;
    } recast;

  return_value = 0;
  target_name_index = 0;

  memset(answer, 0, MAX_DNS_PACKET_BYTES_UDP);
  current_lookup.count = 0;

  if ((target_name_array != NULL) &&
      (target_rbl_array != NULL) &&
      (answer_length = nihdns_query(current_settings, target_name_array, current_settings->current_options->nihdns_query_type_rbl, 0, answer, MAX_DNS_PACKET_BYTES_UDP, &answer_ptr, &target_name_index)) > 0)
    {
    /*
     * This seems silly, but it defeats a strict-aliasing warning from gcc when
     * a more conventional cast is used: (struct nihdns_header *)&answer
     */
    recast.char_ptr = answer;
    num_answers = ntohs((unsigned short)recast.header_ptr->ancount);
    num_cnames = 0;

    exit_loop = 0;
    for (i = 0; (i < num_answers) && !return_value && !exit_loop; i++)
      if ((size = nihdns_skip(answer_ptr, answer + answer_length)) >= 0)
        {
        answer_ptr += size;
        type = NIHDNS_GETINT16(answer_ptr);
        answer_ptr += sizeof(uint16_t);
        answer_ptr += sizeof(uint16_t); /* class */
        answer_ptr += sizeof(uint32_t); /* ttl */
        size = NIHDNS_GETINT16(answer_ptr);
        answer_ptr += sizeof(uint16_t);

        switch (type)
          {
          case NIHDNS_TYPE_TXT:
            txt_length = (char)*answer_ptr;
            answer_ptr++;

            if ((txt_length > 0) &&
                (txt_length < size))
              {
              SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_TXT, target_name_array[target_name_index], MINVAL(txt_length, MAX_BUF - 2), answer_ptr);

              if ((target_message_buf != NULL) &&
                  (size_target_message_buf > 0))
                {
                memcpy(target_message_buf, answer_ptr, MINVAL(txt_length, size_target_message_buf - 2));
                target_message_buf[MINVAL(txt_length, size_target_message_buf - 2)] = '\0';
                }
              if (return_target_name_index != NULL)
                *return_target_name_index = target_name_index;

              return_value = 1;
              answer_ptr += size - 1;
              }
            else if (size == 0)
              SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_EMPTY_DATA, NULL);
            else
              {
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_RESPONSE, target_name_array[target_name_index]);
              exit_loop = 1;
              }

            break;
          case NIHDNS_TYPE_A:
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_A, target_name_array[target_name_index], answer_ptr[0], answer_ptr[1], answer_ptr[2], answer_ptr[3]);

            if ((target_message_buf != NULL) &&
                (size_target_message_buf > 0))
              target_message_buf[0] = '\0';
            if (return_target_name_index != NULL)
              *return_target_name_index = target_name_index;

            return_value = 1;
            answer_ptr += 4;

            break;
          case NIHDNS_TYPE_CNAME:
            cname_ptr[num_cnames] = answer_ptr;
            num_cnames++;

            if ((size = nihdns_skip(answer_ptr, answer + answer_length)) >= 0)
              answer_ptr += size;
            else
              {
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name_array[target_name_index]);
              exit_loop = 1;
              }

            break;
          default:
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_UNKNOWN_TYPE, target_name_array[target_name_index], LOG_MESSAGE_DNS_TYPE_TXT LOG_MESSAGE_DNS_SEPARATOR LOG_MESSAGE_DNS_TYPE_A LOG_MESSAGE_DNS_SEPARATOR LOG_MESSAGE_DNS_TYPE_CNAME, nihdns_type_name(type));
            exit_loop = 1;
            break;
          }
        }
      else
        {
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name_array[target_name_index]);
        break;
        }

    if (return_value &&
        (num_cnames > 0))
      {
      if ((cname_array = (char **)malloc(sizeof(char *) * (num_cnames + 1))) != NULL)
        {
        cname_array[0] = NULL;

        current_lookup.data = target_name_array[target_name_index];
        current_lookup.count++;
        current_lookup.prev = history;

        j = 0;
        for (i = 0; (i < num_cnames) && !return_value; i++)
          if ((size = nihdns_expand(current_settings, answer, answer + answer_length, cname_ptr[i], (char *)host, MAX_HOSTNAME, &strlen_name)) >= 0)
            if ((cname_array[j] = (char *)malloc(sizeof(char) * (strlen_name + 1))) != NULL)
              {
              num_queries = 0;
              tmp_lookup = &current_lookup;
              while (tmp_lookup != NULL)
                {
                num_queries += tmp_lookup->count;
                if (strcasecmp((char *)host, tmp_lookup->data) == 0)
                  break;
                else
                  tmp_lookup = tmp_lookup->prev;
                }

              if ((tmp_lookup == NULL) &&
                  (num_queries < MAX_DNS_QUERIES))
                {
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_CNAME, target_name_array[target_name_index], host);
                memcpy(cname_array[j], host, sizeof(char) * strlen_name);
                cname_array[j][strlen_name] = '\0';
                cname_array[j + 1] = NULL;
                j++;
                }
              else
                break;
              }
            else
              {
              SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char) * (strlen_name + 1));
              return_value = -1;
              break;
              }
          else
            {
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name_array[target_name_index]);
            return_value = -1;
            break;
            }

        if (cname_array[0] != NULL)
          return_value = nihdns_rbl(current_settings, cname_array, target_message_buf, size_target_message_buf, target_rbl_array, return_target_name_index, &current_lookup);

        for (i = 0; (i < num_cnames) && (cname_array[i] != NULL); i++)
          free(cname_array[i]);
        free(cname_array);
        }
      else
        {
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(char *) * (num_cnames + 1));
        return_value = -1;
        }
      }
    }

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int nihdns_ptr_lookup(struct filter_settings *current_settings, char *target_name, struct previous_action *history)
  {
  int return_value;
  int i;
  char answer[MAX_DNS_PACKET_BYTES_UDP];
  char host[MAX_HOSTNAME + 1];
  char *answer_ptr;
  char *cname_ptr[MAX_DNS_QUERIES - 1];
  int num_cnames;
  int answer_length;
  int size;
  int type;
  int num_answers;
  int num_queries;
  int exit_loop;
  int strlen_host;
  struct previous_action current_lookup;
  struct previous_action *tmp_lookup;
  char *target_name_array[2];
  union
    {
    char *char_ptr;
    struct nihdns_header *header_ptr;
    } recast;

  return_value = 0;

  memset(answer, 0, MAX_DNS_PACKET_BYTES_UDP);
  current_lookup.count = 0;

  target_name_array[0] = target_name;
  target_name_array[1] = NULL;

  if ((target_name != NULL) &&
      ((answer_length = nihdns_query(current_settings, target_name_array, current_settings->current_options->nihdns_query_type_ptr, 0, answer, MAX_DNS_PACKET_BYTES_UDP, &answer_ptr, NULL)) > 0))
    {
    /*
     * This seems silly, but it defeats a strict-aliasing warning from gcc when
     * a more conventional cast is used: (struct nihdns_header *)&answer
     */
    recast.char_ptr = answer;
    num_answers = ntohs((unsigned short)recast.header_ptr->ancount);
    num_cnames = 0;

    exit_loop = 0;
    for (i = 0; (i < num_answers) && !return_value && !exit_loop; i++)
      if ((size = nihdns_skip(answer_ptr, answer + answer_length)) >= 0)
        {
        answer_ptr += size; /* qdata */
        type = NIHDNS_GETINT16(answer_ptr);
        answer_ptr += sizeof(uint16_t); /* type */
        answer_ptr += sizeof(uint16_t); /* class */
        answer_ptr += sizeof(uint32_t); /* ttl */
        answer_ptr += sizeof(uint16_t); /* size */

        switch (type)
          {
          case NIHDNS_TYPE_PTR:
            if ((size = nihdns_expand(current_settings, answer, answer + answer_length, answer_ptr, (char *)host, MAX_HOSTNAME, &strlen_host)) > 0)
              if (strlen_host > 0)
                {
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_PTR, target_name, strlen_host, strlen_host, host);

                current_settings->strlen_server_name = strlen_host;
                for (i = 0; i < strlen_host; i++)
                  current_settings->server_name[i] = tolower((int)host[i]);

                current_settings->server_name[current_settings->strlen_server_name] = '\0';

                return_value = 1;
                answer_ptr += size;
                }
              else
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_EMPTY_DATA, NULL);
            else
              {
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
              exit_loop = 1;
              }

            break;
          case NIHDNS_TYPE_CNAME:
            cname_ptr[num_cnames] = answer_ptr;
            num_cnames++;

            if ((size = nihdns_skip(answer_ptr, answer + answer_length)) >= 0)
              answer_ptr += size;
            else
              {
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
              exit_loop = 1;
              }

            break;
          default:
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_UNKNOWN_TYPE, target_name, LOG_MESSAGE_DNS_TYPE_PTR LOG_MESSAGE_DNS_SEPARATOR LOG_MESSAGE_DNS_TYPE_CNAME, nihdns_type_name(type));
            exit_loop = 1;
            break;
          }
        }
      else
        {
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
        break;
        }

    for (i = 0; (i < num_cnames) && !return_value; i++)
      if ((size = nihdns_expand(current_settings, answer, answer + answer_length, cname_ptr[i], (char *)host, MAX_HOSTNAME, NULL)) >= 0)
        {
        current_lookup.data = target_name;
        current_lookup.count++;
        current_lookup.prev = history;

        num_queries = 0;
        tmp_lookup = &current_lookup;
        while (tmp_lookup != NULL)
          {
          num_queries += tmp_lookup->count;
          if (strcasecmp((char *)host, tmp_lookup->data) == 0)
            break;
          else
            tmp_lookup = tmp_lookup->prev;
          }

        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_CNAME, target_name, host);
        return_value = ((tmp_lookup == NULL) && (num_queries < MAX_DNS_QUERIES)) ? nihdns_ptr_lookup(current_settings, (char *)host, &current_lookup) : 0;
        answer_ptr += size;
        }
      else
        {
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
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
int nihdns_ptr(struct filter_settings *current_settings, char *target_ip)
  {
  int return_value;
  char ip_octets[4][4];
  char rdns_name[MAX_RDNS + 1];

  return_value = 0;

  if ((target_ip != NULL) &&
      (sscanf(target_ip, "%3[0-9].%3[0-9].%3[0-9].%3[0-9]", ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]) == 4) &&
      snprintf(rdns_name, MAX_RDNS, "%s.%s.%s.%s%s", ip_octets[3], ip_octets[2], ip_octets[1], ip_octets[0], RDNS_SUFFIX))
    return_value = nihdns_ptr_lookup(current_settings, rdns_name, NULL);

  return(return_value);
  }

/*
 * return_octets must be an array of at least four elements if not NULL.
 *
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int nihdns_a_inner(struct filter_settings *current_settings, char *target_name, int *return_octets, struct previous_action *history, int disqualify_localhost, int target_query_type)
  {
  static int localhost_octets[] = LOCALHOST_OCTETS;
  int return_value;
  int i;
  char answer[MAX_DNS_PACKET_BYTES_UDP];
  char host[MAX_HOSTNAME + 1];
  char *answer_ptr;
  char *cname_ptr[MAX_DNS_QUERIES - 1];
  int num_cnames;
  int answer_length;
  int size;
  int type;
  int num_answers;
  int num_queries;
  int exit_loop;
  struct previous_action current_lookup;
  struct previous_action *tmp_lookup;
  char *target_name_array[2];
  union
    {
    char *char_ptr;
    struct nihdns_header *header_ptr;
    } recast;

  return_value = 0;

  memset(answer, 0, MAX_DNS_PACKET_BYTES_UDP);
  current_lookup.count = 0;

  target_name_array[0] = target_name;
  target_name_array[1] = NULL;

  if ((target_name != NULL) &&
      ((answer_length = nihdns_query(current_settings, target_name_array, target_query_type, 0, answer, MAX_DNS_PACKET_BYTES_UDP, &answer_ptr, NULL)) > 0))
    {
    /*
     * This seems silly, but it defeats a strict-aliasing warning from gcc when
     * a more conventional cast is used: (struct nihdns_header *)&answer
     */
    recast.char_ptr = answer;
    num_answers = ntohs((unsigned short)recast.header_ptr->ancount);
    num_cnames = 0;

    exit_loop = 0;
    for (i = 0; (i < num_answers) && !return_value && !exit_loop; i++)
      if ((size = nihdns_skip(answer_ptr, answer + answer_length)) >= 0)
        {
        answer_ptr += size;
        type = NIHDNS_GETINT16(answer_ptr);
        answer_ptr += sizeof(uint16_t);
        answer_ptr += sizeof(uint16_t); /* class */
        answer_ptr += sizeof(uint32_t); /* ttl */
        size = NIHDNS_GETINT16(answer_ptr);
        answer_ptr += sizeof(uint16_t);

        switch (type)
          {
          case NIHDNS_TYPE_A:
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_A, target_name, answer_ptr[0], answer_ptr[1], answer_ptr[2], answer_ptr[3]);

            if (!disqualify_localhost ||
                (answer_ptr[0] != localhost_octets[0]) ||
                (answer_ptr[1] != localhost_octets[1]) ||
                (answer_ptr[2] != localhost_octets[2]) ||
                (answer_ptr[3] != localhost_octets[3]))
              {
              if (return_octets != NULL)
                {
                return_octets[0] = answer_ptr[0];
                return_octets[1] = answer_ptr[1];
                return_octets[2] = answer_ptr[2];
                return_octets[3] = answer_ptr[3];
                }

              return_value = 1;
              }

            answer_ptr += 4;
            break;
          case NIHDNS_TYPE_CNAME:
            cname_ptr[num_cnames] = answer_ptr;
            num_cnames++;

            if ((size = nihdns_skip(answer_ptr, answer + answer_length)) >= 0)
              answer_ptr += size;
            else
              {
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
              exit_loop = 1;
              }

            break;
          default:
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_UNKNOWN_TYPE, target_name, LOG_MESSAGE_DNS_TYPE_A LOG_MESSAGE_DNS_SEPARATOR LOG_MESSAGE_DNS_TYPE_CNAME, nihdns_type_name(type));
            exit_loop = 1;
            break;
          }
        }
      else
        {
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
        break;
        }

    for (i = 0; (i < num_cnames) && !return_value; i++)
      if ((size = nihdns_expand(current_settings, answer, answer + answer_length, cname_ptr[i], (char *)host, MAX_HOSTNAME, NULL)) >= 0)
        {
        current_lookup.data = target_name;
        current_lookup.count++;
        current_lookup.prev = history;

        num_queries = 0;
        tmp_lookup = &current_lookup;
        while (tmp_lookup != NULL)
          {
          num_queries += tmp_lookup->count;
          if (strcasecmp((char *)host, tmp_lookup->data) == 0)
            break;
          else
            tmp_lookup = tmp_lookup->prev;
          }

        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_CNAME, target_name, host);
        return_value = ((tmp_lookup == NULL) && (num_queries < MAX_DNS_QUERIES)) ? nihdns_a_inner(current_settings, (char *)host, return_octets, &current_lookup, disqualify_localhost, target_query_type) : 0;
        answer_ptr += size;
        }
      else
        {
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
        break;
        }
    }

  return(return_value);
  }

/*
 * return_octets must be an array of at least four elements if not NULL.
 *
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int nihdns_a(struct filter_settings *current_settings, char *target_name, int *return_octets, struct previous_action *history, int disqualify_localhost)
  {
  return(nihdns_a_inner(current_settings, target_name, return_octets, history, disqualify_localhost, current_settings->current_options->nihdns_query_type_a));
  }

/*
 * Return value:
 *   FAILURE: 0
 *   SUCCESS: 1
 */
int nihdns_mx(struct filter_settings *current_settings, char *target_name, struct previous_action *history)
  {
  static int localhost_octets[] = LOCALHOST_OCTETS;
  int return_value;
  int i;
  char answer[MAX_DNS_PACKET_BYTES_UDP];
  char host[MAX_HOSTNAME + 1];
  char *answer_ptr;
  char *cname_ptr[MAX_DNS_QUERIES - 1];
  int num_cnames;
  int answer_length;
  int size;
  int type;
  int num_answers;
  int num_queries;
  int exit_loop;
  int strlen_name;
  struct previous_action current_lookup;
  struct previous_action *tmp_lookup;
  char *target_name_array[2];
  char ip_octets[4][4];
  int ip_ints[4];
  union
    {
    char *char_ptr;
    struct nihdns_header *header_ptr;
    } recast;

  return_value = 0;

  memset(answer, 0, MAX_DNS_PACKET_BYTES_UDP);
  current_lookup.count = 0;

  target_name_array[0] = target_name;
  target_name_array[1] = NULL;

  if ((target_name != NULL) &&
      ((answer_length = nihdns_query(current_settings, target_name_array, current_settings->current_options->nihdns_query_type_mx, NIHDNS_TYPE_MX, answer, MAX_DNS_PACKET_BYTES_UDP, &answer_ptr, NULL)) > 0))
    {
    /*
     * This seems silly, but it defeats a strict-aliasing warning from gcc when
     * a more conventional cast is used: (struct nihdns_header *)&answer
     */
    recast.char_ptr = answer;
    num_answers = ntohs((unsigned short)recast.header_ptr->ancount);
    num_cnames = 0;

    exit_loop = 0;
    for (i = 0; (i < num_answers) && !return_value && !exit_loop; i++)
      if ((size = nihdns_skip(answer_ptr, answer + answer_length)) >= 0)
        {
        answer_ptr += size;
        type = NIHDNS_GETINT16(answer_ptr);
        answer_ptr += sizeof(uint16_t); /* type */
        answer_ptr += sizeof(uint16_t); /* class */
        answer_ptr += sizeof(uint32_t); /* ttl */
        size = NIHDNS_GETINT16(answer_ptr); /* answer length */
        answer_ptr += sizeof(uint16_t); /* answer length */

        switch (type)
          {
          case NIHDNS_TYPE_MX:
            answer_ptr += sizeof(uint16_t); /* MX preference */

            if ((size = nihdns_expand(current_settings, answer, answer + answer_length, answer_ptr, (char *)host, MAX_HOSTNAME, &strlen_name)) > 0)
              {
              if (strlen_name > 0)
                {
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_MX, target_name, NIHDNS_GETINT16(answer_ptr - sizeof(uint16_t)), host);

                if ((sscanf(host, "%3[0-9].%3[0-9].%3[0-9].%3[0-9]", ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]) == 4) &&
                    (sscanf(ip_octets[0], "%d", &ip_ints[0]) == 1) &&
                    (ip_ints[0] >= 0) &&
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
                  SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_MX_IP, host, target_name);

                  if ((ip_ints[0] != localhost_octets[0]) ||
                      (ip_ints[1] != localhost_octets[1]) ||
                      (ip_ints[2] != localhost_octets[2]) ||
                      (ip_ints[3] != localhost_octets[3]))
                    return_value = 1;
                  else
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_MX_LOCALHOST, host);
                  }
                else
                  return_value = nihdns_a_inner(current_settings, (char *)host, NULL, NULL, 1, current_settings->current_options->nihdns_query_type_a);
                }
              else
                SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_EMPTY_DATA, NULL);

              answer_ptr += size;
              }
            else if (size < 0)
              {
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
              exit_loop = 1;
              }

            break;
          case NIHDNS_TYPE_A:
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_A, target_name, answer_ptr[0], answer_ptr[1], answer_ptr[2], answer_ptr[3]);

            if ((answer_ptr[0] != localhost_octets[0]) ||
                (answer_ptr[1] != localhost_octets[1]) ||
                (answer_ptr[2] != localhost_octets[2]) ||
                (answer_ptr[3] != localhost_octets[3]))
              return_value = 1;

            answer_ptr += 4;

            break;
          case NIHDNS_TYPE_CNAME:
            cname_ptr[num_cnames] = answer_ptr;
            num_cnames++;

            if ((size = nihdns_skip(answer_ptr, answer + answer_length)) >= 0)
              answer_ptr += size;
            else
              {
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
              exit_loop = 1;
              }

            break;
          default:
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_UNKNOWN_TYPE, target_name, LOG_MESSAGE_DNS_TYPE_MX LOG_MESSAGE_DNS_SEPARATOR LOG_MESSAGE_DNS_TYPE_A LOG_MESSAGE_DNS_SEPARATOR LOG_MESSAGE_DNS_TYPE_CNAME, nihdns_type_name(type));
            exit_loop = 1;
            break;
          }
        }
      else
        {
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
        break;
        }

    for (i = 0; (i < num_cnames) && !return_value; i++)
      if ((size = nihdns_expand(current_settings, answer, answer + answer_length, cname_ptr[i], (char *)host, MAX_HOSTNAME, NULL)) >= 0)
        {
        current_lookup.data = target_name;
        current_lookup.count++;
        current_lookup.prev = history;

        num_queries = 0;
        tmp_lookup = &current_lookup;
        while (tmp_lookup != NULL)
          {
          num_queries += tmp_lookup->count;
          if (strcasecmp((char *)host, tmp_lookup->data) == 0)
            break;
          else
            tmp_lookup = tmp_lookup->prev;
          }

        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_DNS_CNAME, target_name, host);
        return_value = ((tmp_lookup == NULL) && (num_queries < MAX_DNS_QUERIES)) ? nihdns_mx(current_settings, (char *)host, &current_lookup) : 0;
        answer_ptr += size;
        }
      else
        {
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_VERBOSE_DNS_COMPRESSION, target_name);
        break;
        }
    }

  return(return_value);
  }
