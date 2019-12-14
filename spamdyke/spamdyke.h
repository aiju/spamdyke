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
#ifndef SPAMDYKE_H
#define SPAMDYKE_H

#include "config.h"
#include <stdio.h>

#ifdef HAVE_STDINT_H

#include <stdint.h>

#else /* HAVE_STDINT_H */

#define INT32_MAX        2147483647

#endif /* HAVE_STDINT_H */

#include <sys/types.h>
#include <netinet/in.h>

#ifdef HAVE_GETOPT_H

#define _GNU_SOURCE
#include <getopt.h>

#else /* HAVE_GETOPT_H */

#include <unistd.h>

#endif /* HAVE_GETOPT_H */

#ifdef HAVE_LIBSSL

#include <openssl/ssl.h>

#define VERSION_TLS                     "+TLS"

#else /* HAVE_LIBSSL */

#define VERSION_TLS                     ""

#endif /* HAVE_LIBSSL */

#ifndef WITHOUT_CONFIG_TEST

#define VERSION_CONFIGTEST              "+CONFIGTEST"

#else /* WITHOUT_CONFIG_TEST */

#define VERSION_CONFIGTEST              ""

#endif /* WITHOUT_CONFIG_TEST */

#ifndef WITHOUT_DEBUG_OUTPUT

#define VERSION_DEBUG                   "+DEBUG"

#else /* WITHOUT_DEBUG_OUTPUT */

#define VERSION_DEBUG                   ""

#endif /* WITHOUT_DEBUG_OUTPUT */

#ifdef WITH_EXCESSIVE_OUTPUT

#define VERSION_EXCESSIVE               "+EXCESSIVE"

#else /* WITH_EXCESSIVE_OUTPUT */

#define VERSION_EXCESSIVE               ""

#endif /* WITH_EXCESSIVE_OUTPUT */

#ifdef WITH_ADDRESS_SANITIZER

#define VERSION_SANITIZER               "+SANITIZER"

#else /* WITH_ADDRESS_SANITIZER */

#define VERSION_SANITIZER               ""

#endif /* WITH_ADDRESS_SANITIZER */

#define VERSION_STRING                  PACKAGE_VERSION VERSION_TLS VERSION_CONFIGTEST VERSION_DEBUG VERSION_EXCESSIVE VERSION_SANITIZER

#define STRLEN(X)                       ((int)(sizeof(X) - 1))
#define _STRINGIFY(X)                   #X
#define STRINGIFY(X)                    _STRINGIFY(X)

#define DEFAULT_REMOTE_IP               "0.0.0.0"
#define DEFAULT_PATH                    "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/var/qmail/bin:/home/vpopmail/bin"
#define DEFAULT_NIHDNS_RESOLVER_FILENAME        "/etc/resolv.conf"
#define DEFAULT_NIHDNS_PORT             53
#define DEFAULT_TIMEOUT_NIHDNS_TOTAL_SECS       30
#define DEFAULT_NIHDNS_ATTEMPTS_PRIMARY 1
#define DEFAULT_NIHDNS_ATTEMPTS_TOTAL   3
#define DEFAULT_TLS_CIPHER_LIST         "DEFAULT"
#define DEFAULT_QMAIL_MORERCPTHOSTS_CDB "/var/qmail/control/morercpthosts.cdb"
#define DEFAULT_QMAIL_RCPTHOSTS_FILE    "/var/qmail/control/rcpthosts"

#define TIMEOUT_CHECKPASSWORD_SECS      30
#define TIMEOUT_TLS_SHUTDOWN_SECS       5
#define TIMEOUT_COMMAND_SECS            30
#define TIMEOUT_IDLE_AFTER_QUIT_SECS    1200
#define TIMEOUT_COMMAND_EXIT_USECS      100000

#define MIN_SELECT_SECS_TIMEOUT         0
#define MIN_SELECT_USECS_TIMEOUT        500000
#define MAX_SELECT_SECS_TIMEOUT         2
#define MAX_SELECT_USECS_TIMEOUT        0
#define SELECT_SECS_NO_TIMEOUT          2
#define SELECT_USECS_NO_TIMEOUT         0

#define ENVIRONMENT_DELIMITER           '='
#define ENVIRONMENT_DELIMITER_STRING    "="
#define ENVIRONMENT_REMOTE_IP_TCPSERVER "TCPREMOTEIP"
#define ENVIRONMENT_REMOTE_IP_OLD_INETD "REMOTE_HOST"
#define ENVIRONMENT_REMOTE_IP           { ENVIRONMENT_REMOTE_IP_TCPSERVER, ENVIRONMENT_REMOTE_IP_OLD_INETD, NULL }
#define STRLEN_ENVIRONMENT_REMOTE_IP    { STRLEN(ENVIRONMENT_REMOTE_IP_TCPSERVER), STRLEN(ENVIRONMENT_REMOTE_IP_OLD_INETD), -1 }
#define ENVIRONMENT_REMOTE_NAME         "TCPREMOTEHOST"
#define ENVIRONMENT_REMOTE_INFO         "TCPREMOTEINFO"
#define ENVIRONMENT_LOCAL_PORT          "TCPLOCALPORT"
#define ENVIRONMENT_LOCAL_PORT_SMTP     "TCPLOCALPORT=25"
#define ENVIRONMENT_PATH                "PATH"
#define ENVIRONMENT_ALLOW_RELAY         "RELAYCLIENT"
#define ENVIRONMENT_HOSTNAME_TCPSERVER  "TCPLOCALHOST"
#define ENVIRONMENT_HOSTNAME_LINUX      "HOSTNAME"
#define ENVIRONMENT_HOSTNAME            (char *[]){ ENVIRONMENT_HOSTNAME_TCPSERVER, ENVIRONMENT_HOSTNAME_LINUX, NULL }
#define STRLEN_ENVIRONMENT_HOSTNAME     (int []){ STRLEN(ENVIRONMENT_HOSTNAME_TCPSERVER), STRLEN(ENVIRONMENT_HOSTNAME_LINUX), -1 }
#define ENVIRONMENT_RESOLV_OPTION       "RES_OPTIONS"
#define ENVIRONMENT_SMTPS               "SMTPS"

#define TCPRULES_INFO                   '@'
#define TCPRULES_ENVIRONMENT            ':'
#define TCPRULES_NAME                   '='

#define COMMAND_LINE_SPACER             ','
#define COMMAND_LINE_TRUE               "1tTyY"
#define COMMAND_LINE_FALSE              "0fFnN"

#define STDIN_FD                        0
#define STDOUT_FD                       1
#define STDERR_FD                       2
#define CHECKPASSWORD_FD                3

#define CHAR_CR                         '\r'
#define CHAR_LF                         '\n'
#define STR_CRLF                        "\r\n"

#define MKDIR_MODE                      0700
#define CHMOD_MODE                      0600
#define DIR_CURRENT                     "."
#define DIR_PARENT                      ".."
#define DIR_DELIMITER                   '/'
#define DIR_DELIMITER_STR               "/"
#define USER_DELIMITER                  ":"

#define FILE_PERMISSION_STICKY          0x20
#define FILE_PERMISSION_SETUID          0x10
#define FILE_PERMISSION_SETGID          0x08
#define FILE_PERMISSION_READ            0x04
#define FILE_PERMISSION_WRITE           0x02
#define FILE_PERMISSION_EXECUTE         0x01

#define CONFIG_VALUE_CANCEL             "!!!"
#define CONFIG_VALUE_REMOVE             "!"

#define CONFIG_DIR_IP                   "_ip_"
#define CONFIG_DIR_NAME                 "_rdns_"
#define CONFIG_DIR_SENDER               "_sender_"
#define CONFIG_DIR_RECIPIENT            "_recipient_"
#define CONFIG_DIR_USERNAME             "_at_"

#define CONFIG_DIR_SEARCH_FIRST         0x00
#define CONFIG_DIR_SEARCH_ALL_IP        0x01
#define CONFIG_DIR_SEARCH_ALL_RDNS      0x02
#define CONFIG_DIR_SEARCH_ALL_SENDER    0x04
#define CONFIG_DIR_SEARCH_ALL_RECIPIENT 0x08

#define REJECT_SENDER_NONE              0x00
#define REJECT_SENDER_NO_MX             0x01
#define REJECT_SENDER_NOT_LOCAL         0x02
#define REJECT_SENDER_NOT_AUTH          0x04
#define REJECT_SENDER_NOT_AUTH_DOMAIN   0x08

#define REJECT_RECIPIENT_NONE           0x00
#define REJECT_RECIPIENT_SAME_AS_SENDER 0x01
#define REJECT_RECIPIENT_INVALID        0x02
#define REJECT_RECIPIENT_UNAVAILABLE    0x04

#define COMMENT_DELIMITER               '#'
#define VALUE_DELIMITER                 "="
#define RESOLVER_FILE_COMMENT_DELIMITER_1       '#'
#define RESOLVER_FILE_COMMENT_DELIMITER_2       ';'

#define REASON_REPLACE_TARGET           ' '
#define REASON_REPLACE_REPLACEMENT      '_'

#define HEADER_DELIMITER                ':'

#define MAX_ADDRESS                     511
#define MAX_PATH                        4095
#define MAX_BUF                         1023
#define MAX_NETWORK_BUF                 16383
/* MAX_RETAIN_BUF should be evenly divisible by MAX_NETWORK_BUF */
#define MAX_RETAIN_BUF                  524256
#define MAX_FILE_BUF                    65535
#define MAX_FILE_LINES                  65536
#define MAX_POLICY                      100
#define MAX_RDNS                        29
#define MAX_IP                          15
#define MAX_CHECKPASSWORD               511
#define MAX_COMMAND_BUF                 4095
#define MAX_RAND_SEED                   65536
#define MAX_HOSTNAME                    127
#define MAX_BUF_SOCKET                  32768

#define MAX_NIHDNS_SERVERS              16
#define MAX_DNS_QUERIES                 16
#define MAX_DNS_PACKET_BYTES_UDP        512
#define MAX_DNS_PACKET_BYTES_TCP        65536

#define RDNS_SUFFIX                     ".in-addr.arpa"
#define MINVAL(a,b)                     ({ typeof (a) _a = (a); typeof (b) _b = (b); _a < _b ? _a : _b; })
#define MAXVAL(a,b)                     ({ typeof (a) _a = (a); typeof (b) _b = (b); _a > _b ? _a : _b; })

/*
 * The return value of snprintf() gives the number of bytes that would be needed
 * to print everything, if space were infinite.  That value may be much larger
 * than the actual number of bytes printed, if the buffer was too small to hold
 * everything.  Putting %n at the end of the format string just gives the same
 * value as the return value of the function.  In a word, useless.  In another
 * word, dangerous.  Using the return value as a replacement for strlen() can
 * cause segfaults (best case) or buffer overflows (worst case).
 *
 * So this macro exists to give number of bytes actually printed into the
 * buffer, which can be used as a string length.
 */
#define SNPRINTF(BUF,MAX,FORMAT...)     ({ int _tmp = snprintf(BUF, MAX, FORMAT); MINVAL(_tmp, MAX); })

#define BATV_PREFIX                     "prvs="

#define MD5_IPAD_BYTE                   0x36
#define MD5_OPAD_BYTE                   0x5C

#define PATH_ESCAPE_CHAR                '\\'
#define PATH_QUOTE_CHAR                 '"'

#define USAGE_LEVEL_SHORT               0
#define USAGE_LEVEL_BRIEF               1
#define USAGE_LEVEL_LONG                2

#define USAGE_LINE_WRAP                 80
#define USAGE_LINE_INDENT               "  "
#define USAGE_MESSAGE_HEADER            "spamdyke " VERSION_STRING " (C)2015 Sam Clippinger, " PACKAGE_BUGREPORT "\nhttp://www.spamdyke.org/\n\n"
#define USAGE_MESSAGE_USAGE             "USAGE: spamdyke [ OPTIONS ] [ -- ] qmail_smtpd_command [ qmail_smtpd_arguments ]\n\nAvailable options:\n"
#define USAGE_MESSAGE_INTEGER_RANGE     "%s must be between (or equal to) %d and %d.\n"
#define USAGE_MESSAGE_NAME_VALUE_DELIMITER      " | "
#define USAGE_MESSAGE_OPTIONAL_SHORT    "No spaces are allowed between '%c' and %s.\n"
#define USAGE_MESSAGE_OPTIONAL_LONG     "No spaces are allowed and an equals sign is required between %s and %s.\n"
#define USAGE_MESSAGE_ARRAY             "%s may be used multiple times.\n"
#define USAGE_MESSAGE_SINGLETON         "%s may only be used once.\n"
#define USAGE_MESSAGE_FOOTER_SHORT      "Use --help for an option summary, --more-help for option details or see README.html for complete documentation.\n\n"
#define USAGE_MESSAGE_FOOTER_BRIEF      "\nUse --more-help for option details or see README.html for complete documentation.\n\n"
#define USAGE_MESSAGE_FOOTER_LONG       "\nSee README.html for a complete explanation of these options.\n"

/*
 * The FILTER_* values are returned by smtp_filter() and interpreted by
 * middleman().  These values are ORed together and separated by ANDing the
 * FILTER_MASK_* value to reveal the set value.  For that reason, it is very
 * important that none of the FILTER_FLAG_* values use bits that aren't
 * covered by its FILTER_MASK_* value.  And of course none of them should
 * overlap.
 */
#define FILTER_MASK_PASS                0x07
/* PASS is implied in assignments if another flag is not specified. */
/* PASS = send the data to qmail */
#define FILTER_FLAG_PASS                0x00
/* INTERCEPT = delete the data; do not send to qmail */
#define FILTER_FLAG_INTERCEPT           0x01
/* RETAIN = buffer the data for future processing; do not send to qmail yet */
#define FILTER_FLAG_RETAIN              0x02
/* QUIT = exit spamdyke entirely (due to error) */
#define FILTER_FLAG_QUIT                0x04

#define FILTER_MASK_CHILD               0x08
/* CHILD_CONTINUE is implied in assignments if CHILD_QUIT is not specified. */
/* CHILD_CONTINUE = maintain connection with qmail process */
#define FILTER_FLAG_CHILD_CONTINUE      0x00
/* CHILD_QUIT = signal qmail to quit and close the connection; intercept all future data */
#define FILTER_FLAG_CHILD_QUIT          0x08

/* AUTH values allow multiple flags to be set simultaneously. */
#define FILTER_MASK_AUTH                0x70
/* AUTH_NONE is implied in assignments if another flag is not specified. */
/* AUTH_NONE = ignore SMTP AUTH commands */
#define FILTER_FLAG_AUTH_NONE           0x00
/* AUTH_ADD = add an SMTP AUTH banner if none is sent by qmail (or if qmail's is removed by spamdyke) */
#define FILTER_FLAG_AUTH_ADD            0x10
/* AUTH_CAPTURE = monitor/process SMTP AUTH data to determine if authentication succeeds */
#define FILTER_FLAG_AUTH_CAPTURE        0x20
/* AUTH_REMOVE = remove all SMTP AUTH banners and commands */
#define FILTER_FLAG_AUTH_REMOVE         0x40

#define FILTER_MASK_TLS                 0x0180
/* TLS_NONE is implied in assignments if another flag is not specified. */
/* TLS_NONE = ignore TLS commands */
#define FILTER_FLAG_TLS_NONE            0x0000
/* TLS_ADD = add a TLS banner if none is sent by qmail */
#define FILTER_FLAG_TLS_ADD             0x0080
/* TLS_CAPTURE = monitor TLS commands and pass encrypted traffic through without processing */
#define FILTER_FLAG_TLS_CAPTURE         0x0100
/* TLS_REMOVE = remove all TLS banners and commands */
#define FILTER_FLAG_TLS_REMOVE          0x0180

#define FILTER_MASK_RCPT                0x0200
/* RCPT_NONE is implied in assignments if another flag is not specified. */
/* RCPT_NONE = ignore recipient commands */
#define FILTER_FLAG_RCPT_NONE           0x0000
/* RCPT_CAPTURE = monitor qmail's response to a recipient command */
#define FILTER_FLAG_RCPT_CAPTURE        0x0200

#define FILTER_MASK_CHILD_RESPONSE      0x0C00
/* CHILD_RESPONSE_NEEDED is implied in assignments if another flag is not specified. */
/* CHILD_RESPONSE_NEEDED = middleman() should expect a response from qmail before processing any more commands from the remote server */
#define FILTER_FLAG_CHILD_RESPONSE_NEEDED       0x0000
/* CHILD_RESPONSE_NOT_NEEDED = middleman() should continue sending commands from the remote server without waiting for qmail's response */
#define FILTER_FLAG_CHILD_RESPONSE_NOT_NEEDED   0x0400
/* CHILD_RESPONSE_INTERCEPT = middleman() should discard the next response from qmail */
#define FILTER_FLAG_CHILD_RESPONSE_INTERCEPT    0x0800

#define FILTER_MASK_CLEAR               0x1000
/* KEEP is implied in assignments if another flag is not specified. */
/* KEEP = retain any buffered data from the remote server and continue processing it */
#define FILTER_FLAG_KEEP                0x0000
/* CLEAR = delete any buffered data from the remote server and wait for more */
#define FILTER_FLAG_CLEAR               0x1000

#define FILTER_MASK_DATA                0x2000
/* DATA_NONE is implied in assignments if another flag is not specified. */
/* DATA_NONE = ignore data commands */
#define FILTER_FLAG_DATA_NONE           0x0000
/* DATA_CAPTURE = monitor qmail's response to a data command */
#define FILTER_FLAG_DATA_CAPTURE        0x2000

/*
 * The values of these constants are significant.  set_config_value() and
 * filter_*() use them to decide if the filter action should be set by comparing
 * the current value to the new value.  If the new value is greater than the
 * current value, the filter action is set.  Otherwise, it is not.
 *
 * When FILTER_DECISION_TRANSIENT_DO_FILTER is set, transient_rejection must also be set.
 * When FILTER_DECISION_DO_FILTER is set, rejection must also be set.
 */
/* UNDECIDED: processing should continue, no decision has been reached yet. */
#define FILTER_DECISION_UNDECIDED               0
/* TRANSIENT_DO_FILTER: block the incoming message for the current recipient only, then revert back to UNDECIDED. */
#define FILTER_DECISION_TRANSIENT_DO_FILTER     1
/* DO_FILTER: block the entire incoming message. */
#define FILTER_DECISION_DO_FILTER               2
/* AUTHENTICATED: allow the entire incoming message due to successful authentication. */
#define FILTER_DECISION_AUTHENTICATED           3
/* TRANSIENT_DO_NOT_FILTER: allow the incoming message for the current recipient only, then revert back to the previous value. */
#define FILTER_DECISION_TRANSIENT_DO_NOT_FILTER 4
/* WHITELISTED: allow the entire incoming message due to a whitelist match. */
#define FILTER_DECISION_WHITELISTED             5
/* CONFIG_TEST: the config-test option was used; run the tests and exit. */
#define FILTER_DECISION_CONFIG_TEST             6
/* FORK_ERROR: an error occurred while trying to start qmail; log the error and try to start qmail without spamdyke. */
#define FILTER_DECISION_FORK_ERROR              7
/* ERROR: a serious error occurred, probably unable to allocate memory; log the error (if possible) and exit. */
#define FILTER_DECISION_ERROR                   8

/*
 * The values of these constants must be in ascending order.
 */
#define FILTER_GRACE_EXPIRED            -1
#define FILTER_GRACE_NONE               0
#define FILTER_GRACE_AFTER_FROM         1
#define FILTER_GRACE_AFTER_TO           2
#define FILTER_GRACE_AFTER_DATA         3

#define FILTER_LEVEL_NORMAL             1
#define FILTER_LEVEL_ALLOW_ALL          2
#define FILTER_LEVEL_REQUIRE_AUTH       3
#define FILTER_LEVEL_REJECT_ALL         4

#define GRAYLIST_LEVEL_NONE             0x01

#define GRAYLIST_LEVEL_MASK_BEHAVIOR    0x18
#define GRAYLIST_LEVEL_FLAG_ALWAYS      0x08
#define GRAYLIST_LEVEL_FLAG_ONLY        0x10

#define GRAYLIST_LEVEL_MASK_CREATION    0x06
#define GRAYLIST_LEVEL_FLAG_NO_CREATE   0x02
#define GRAYLIST_LEVEL_FLAG_CREATE      0x04

#define TLS_STATE_INACTIVE              0
#define TLS_STATE_ACTIVE_SPAMDYKE       1
#define TLS_STATE_ACTIVE_PASSTHROUGH    2

#define TLS_LEVEL_NONE                  1
#define TLS_LEVEL_PROTOCOL              2
#define TLS_LEVEL_PROTOCOL_SPAMDYKE     3
#define TLS_LEVEL_SMTPS                 4

#define TLS_DESC_UNKNOWN                "(unknown)"
#define TLS_DESC_INACTIVE               "(none)"
#define TLS_DESC_PASSTHROUGH            "TLS_PASSTHROUGH"
#define TLS_DESC_SPAMDYKE_PROTOCOL      "TLS"
#define TLS_DESC_SPAMDYKE_SMTPS         "SSL"

#define LOCALHOST_IP                    "127.0.0.1"
#define LOCALHOST_OCTETS                { 127, 0, 0, 1 }
#define LOCALHOST_NAME                  "localhost"
#define MISSING_LOCAL_SERVER_NAME       "unknown.server.unknown.domain"

#define ALPHABET_FILENAME               "abcdefghijklmnopqrstuvwxyz0123456789@_-.ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define REPLACEMENT_FILENAME            '_'
#define ALPHABET_BASE64                 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define PAD_BASE64                      '='

#define REJECT_SEVERITY_NONE            "250 "
#define REJECT_SEVERITY_HELO            "220 "
#define REJECT_SEVERITY_QUIT            "221 "
#define REJECT_SEVERITY_AUTH_SUCCESS    "235 "
#define REJECT_SEVERITY_AUTH_CHALLENGE  "334 "
#define REJECT_SEVERITY_TEMPORARY       "421 "
#define REJECT_SEVERITY_AUTH_UNKNOWN    "504 "
#define REJECT_SEVERITY_AUTH_FAILURE    "535 "
#define REJECT_SEVERITY_PERMANENT       "554 "
#define REJECT_SEVERITY_TLS_SUCCESS     "220 "
#define REJECT_SEVERITY_TLS_FAILURE     "454 "
#define REJECT_SEVERITY_DATA_SUCCESS    "354 "
#define STRLEN_REJECT_SEVERITY          4
#define REJECT_CRLF                     "\r\n"

#define SMTP_HELO                       "HELO"
#define SMTP_EHLO                       "EHLO"
#define SMTP_AUTH                       "AUTH"
#define SMTP_TLS                        "STARTTLS"
#define SMTP_MAIL_FROM                  "MAIL FROM"
#define SMTP_RCPT_TO                    "RCPT TO"
#define SMTP_DATA                       "DATA"
#define SMTP_DATA_END                   "."
#define SMTP_QUIT                       "QUIT"
#define SMTP_RSET                       "RSET"

/* These constants must be in ascending order. */
#define SMTP_AUTH_LEVEL_MASK                            0x07
#define SMTP_AUTH_LEVEL_VALUE_NONE                      0x01
#define SMTP_AUTH_LEVEL_VALUE_OBSERVE                   0x02
#define SMTP_AUTH_LEVEL_VALUE_ON_DEMAND                 0x03
#define SMTP_AUTH_LEVEL_VALUE_ON_DEMAND_ENCRYPTED       0x04
#define SMTP_AUTH_LEVEL_VALUE_ALWAYS                    0x05
#define SMTP_AUTH_LEVEL_VALUE_ALWAYS_ENCRYPTED          0x06

/*
 * The integer value 0 must match the UNSET value because prepare_settings()
 * sets smtp_auth_level to 0 before processing the command line.  The extra
 * action for smtp-auth-command conditionally sets smtp_auth_level if it
 * matches the UNSET value.
 *
 * However, after the command line has been processed, smtp_auth_level is
 * set to a default if it wasn't set.  The action for smtp-auth-command
 * still needs to set smtp_auth_level from a configuration file, so UNSET
 * must also be valid there.
 */
#define SMTP_AUTH_SET_MASK                      0x08
#define SMTP_AUTH_SET_VALUE_UNSET               0x00
#define SMTP_AUTH_SET_VALUE_SET                 0x08

#define SMTP_AUTH_UNKNOWN               -1
#define SMTP_AUTH_LOGIN                 0
#define SMTP_AUTH_PLAIN                 1
#define SMTP_AUTH_CRAM_MD5              2
#define SMTP_AUTH_TYPE_LOGIN            "LOGIN"
#define SMTP_AUTH_TYPE_PLAIN            "PLAIN"
#define SMTP_AUTH_TYPE_CRAM_MD5         "CRAM-MD5"
#define SMTP_AUTH_TYPES                 (char *[]){ SMTP_AUTH_TYPE_LOGIN, SMTP_AUTH_TYPE_PLAIN, SMTP_AUTH_TYPE_CRAM_MD5, NULL }
#define STRLEN_SMTP_AUTH_TYPES          (int []){ STRLEN(SMTP_AUTH_TYPE_LOGIN), STRLEN(SMTP_AUTH_TYPE_PLAIN), STRLEN(SMTP_AUTH_TYPE_CRAM_MD5), -1 }

#define SMTP_AUTH_LOGIN_CHALLENGE_1             "VXNlcm5hbWU6"
#define SMTP_AUTH_LOGIN_CHALLENGE_2             "UGFzc3dvcmQ6"

#define SMTP_AUTH_ORIGIN_NONE           0
#define SMTP_AUTH_ORIGIN_SPAMDYKE       1
#define SMTP_AUTH_ORIGIN_CHILD          2

#define SMTP_AUTH_STATE_UNKNOWN                 -1
#define SMTP_AUTH_STATE_NONE                    0
#define SMTP_AUTH_STATE_CMD_SEEN                1
#define SMTP_AUTH_STATE_CHALLENGE_1_SENT        2
#define SMTP_AUTH_STATE_RESPONSE_1_SEEN         3
#define SMTP_AUTH_STATE_CHALLENGE_2_SENT        4
#define SMTP_AUTH_STATE_RESPONSE_2_SEEN         5
#define SMTP_AUTH_STATE_AUTHENTICATED           6

#define SMTP_CONTINUATION               '-'
#define SMTP_STR_CONTINUATION           "-"
#define SMTP_STR_DONE                   " "
#define SMTP_EHLO_SUCCESS               "250"
#define SMTP_EHLO_AUTH_CORRECT          "AUTH "
#define SMTP_EHLO_AUTH_INCORRECT        "AUTH="
#define SMTP_EHLO_TLS                   "STARTTLS"
#define SMTP_EHLO_AUTH_INSERT_ENCRYPTION        "AUTH LOGIN PLAIN CRAM-MD5\r\n"
#define SMTP_EHLO_AUTH_INSERT_CLEAR     "AUTH LOGIN PLAIN\r\n"
#define SMTP_EHLO_TLS_INSERT            "STARTTLS\r\n"
#define SMTP_EHLO_NOTHING_INSERT        "X-NOTHING\r\n"
#define SMTP_AUTH_CHALLENGE             "334"
#define SMTP_AUTH_SUCCESS               "235"
#define SMTP_AUTH_PROMPT                "3"
#define SMTP_AUTH_FAILURE               "5"
#define SMTP_TLS_SUCCESS                "220"
#define SMTP_RCPT_SUCCESS               "250"
#define SMTP_DATA_SUCCESS               "250"

#define CHILD_QUIT                      ".\r\nQUIT\r\n"

#define SENDER_ADDRESS_NONE             "_none"
#define SENDER_DOMAIN_NONE              "_none"
#define SENDER_DOMAIN_NONE_TEMP         "___none"

#define SHORT_SUCCESS                   "ALLOWED"
#define SHORT_TLS_PASSTHROUGH           "TLS_ENCRYPTED"

#define ERROR_URL                       " See: "
#define ERROR_URL_DELIMITER_DYNAMIC     '='
#define ERROR_URL_DELIMITER_STATIC      "#"

struct rejection_data
  {
  int rejection_index;
  char *reject_severity;
  char *reject_message;
  int strlen_reject_message;
  char *short_reject_message;
  int append_policy;
  char *reject_reason;
  int strlen_reject_reason;
  };

#define SUCCESS_AUTH                    { -1, REJECT_SEVERITY_AUTH_SUCCESS, "Proceed.", 8, SHORT_SUCCESS "_AUTHENTICATED", 0, NULL, 0 }
#define SUCCESS_TLS                     { -2, REJECT_SEVERITY_TLS_SUCCESS, "Proceed.", 8, SHORT_SUCCESS "_TLS", 0, NULL, 0 }
#define SUCCESS_DATA                    { -3, REJECT_SEVERITY_DATA_SUCCESS, "Proceed.", 8, SHORT_SUCCESS "_DATA", 0, NULL, 0 }

#define REJECTION_UNPARSEABLE                   0
#define ERROR_UNPARSEABLE                       "Unable to parse input. Please verify input format is correct."
#define REJECTION_DATA_UNPARSEABLE              { REJECTION_UNPARSEABLE, REJECT_SEVERITY_PERMANENT, ERROR_UNPARSEABLE, STRLEN(ERROR_UNPARSEABLE), "DENIED_UNPARSEABLE", 0, NULL, 0 }

#define REJECTION_RCPT_TO                       1
#define ERROR_RCPT_TO                           "Too many recipients. Try the remaining addresses again later."
#define REJECTION_DATA_RCPT_TO                  { REJECTION_RCPT_TO, REJECT_SEVERITY_TEMPORARY, ERROR_RCPT_TO, STRLEN(ERROR_RCPT_TO), "DENIED_TOO_MANY_RECIPIENTS", 1, NULL, 0 }

#define REJECTION_RCPT_TO_LOCAL                 2
#define ERROR_RCPT_TO_LOCAL                     "Improper recipient address. Try supplying a domain name."
#define REJECTION_DATA_RCPT_TO_LOCAL            { REJECTION_RCPT_TO_LOCAL, REJECT_SEVERITY_PERMANENT, ERROR_RCPT_TO_LOCAL, STRLEN(ERROR_RCPT_TO_LOCAL), "DENIED_UNQUALIFIED_RECIPIENT", 1, NULL, 0 }

#define REJECTION_GRAYLISTED                    3
#define ERROR_GRAYLISTED                        "Your address has been graylisted. Try again later."
#define REJECTION_DATA_GRAYLISTED               { REJECTION_GRAYLISTED, REJECT_SEVERITY_TEMPORARY, ERROR_GRAYLISTED, STRLEN(ERROR_GRAYLISTED), "DENIED_GRAYLISTED", 1, NULL, 0 }

#define REJECTION_RDNS_MISSING                  4
#define ERROR_RDNS_MISSING                      "Refused. You have no reverse DNS entry."
#define REJECTION_DATA_RDNS_MISSING             { REJECTION_RDNS_MISSING, REJECT_SEVERITY_TEMPORARY, ERROR_RDNS_MISSING, STRLEN(ERROR_RDNS_MISSING), "DENIED_RDNS_MISSING", 1, NULL, 0 }

#define REJECTION_RDNS_RESOLVE                  5
#define ERROR_RDNS_RESOLVE                      "Refused. Your reverse DNS entry does not resolve."
#define REJECTION_DATA_RDNS_RESOLVE             { REJECTION_RDNS_RESOLVE, REJECT_SEVERITY_TEMPORARY, ERROR_RDNS_RESOLVE, STRLEN(ERROR_RDNS_RESOLVE), "DENIED_RDNS_RESOLVE", 1, NULL, 0 }

#define REJECTION_IP_IN_NAME_CC                 6
#define ERROR_IP_IN_NAME_CC                     "Refused. Your reverse DNS entry contains your IP address and a country code."
#define REJECTION_DATA_IP_IN_NAME_CC            { REJECTION_IP_IN_NAME_CC, REJECT_SEVERITY_PERMANENT, ERROR_IP_IN_NAME_CC, STRLEN(ERROR_IP_IN_NAME_CC), "DENIED_IP_IN_CC_RDNS", 1, NULL, 0 }

#define REJECTION_IP_IN_NAME                    7
#define ERROR_IP_IN_NAME                        "Refused. Your reverse DNS entry contains your IP address and a banned keyword."
#define REJECTION_DATA_IP_IN_NAME               { REJECTION_IP_IN_NAME, REJECT_SEVERITY_PERMANENT, ERROR_IP_IN_NAME, STRLEN(ERROR_IP_IN_NAME), "DENIED_IP_IN_RDNS", 1, NULL, 0 }

#define REJECTION_EARLYTALKER                   8
#define ERROR_EARLYTALKER                       "Refused. You are not following the SMTP protocol."
#define REJECTION_DATA_EARLYTALKER              { REJECTION_EARLYTALKER, REJECT_SEVERITY_PERMANENT, ERROR_EARLYTALKER, STRLEN(ERROR_EARLYTALKER), "DENIED_EARLYTALKER", 1, NULL, 0 }

#define REJECTION_BLACKLIST_NAME                9
#define ERROR_BLACKLIST_NAME                    "Refused. Your domain name is blacklisted."
#define REJECTION_DATA_BLACKLIST_NAME           { REJECTION_BLACKLIST_NAME, REJECT_SEVERITY_PERMANENT, ERROR_BLACKLIST_NAME, STRLEN(ERROR_BLACKLIST_NAME), "DENIED_BLACKLIST_NAME", 1, NULL, 0 }

#define REJECTION_BLACKLIST_IP                  10
#define ERROR_BLACKLIST_IP                      "Refused. Your IP address is blacklisted."
#define REJECTION_DATA_BLACKLIST_IP             { REJECTION_BLACKLIST_IP, REJECT_SEVERITY_PERMANENT, ERROR_BLACKLIST_IP, STRLEN(ERROR_BLACKLIST_IP), "DENIED_BLACKLIST_IP", 1, NULL, 0 }

#define REJECTION_TIMEOUT                       11
#define ERROR_TIMEOUT                           "Timeout. Talk faster next time."
#define REJECTION_DATA_TIMEOUT                  { REJECTION_TIMEOUT, REJECT_SEVERITY_TEMPORARY, ERROR_TIMEOUT, STRLEN(ERROR_TIMEOUT), "TIMEOUT", 1, NULL, 0 }

#define REJECTION_SENDER_BLACKLISTED            12
#define ERROR_SENDER_BLACKLISTED                "Refused. Your sender address has been blacklisted."
#define REJECTION_DATA_SENDER_BLACKLISTED       { REJECTION_SENDER_BLACKLISTED, REJECT_SEVERITY_PERMANENT, ERROR_SENDER_BLACKLISTED, STRLEN(ERROR_SENDER_BLACKLISTED), "DENIED_SENDER_BLACKLISTED", 1, NULL, 0 }

#define REJECTION_RECIPIENT_BLACKLISTED         13
#define ERROR_RECIPIENT_BLACKLISTED             "Refused. Mail is not being accepted at this address."
#define REJECTION_DATA_RECIPIENT_BLACKLISTED    { REJECTION_RECIPIENT_BLACKLISTED, REJECT_SEVERITY_PERMANENT, ERROR_RECIPIENT_BLACKLISTED, STRLEN(ERROR_RECIPIENT_BLACKLISTED), "DENIED_RECIPIENT_BLACKLISTED", 1, NULL, 0 }

#define REJECTION_SENDER_NO_MX                  14
#define ERROR_SENDER_NO_MX                      "Refused. The domain of your sender address has no mail exchanger (MX)."
#define REJECTION_DATA_SENDER_NO_MX             { REJECTION_SENDER_NO_MX, REJECT_SEVERITY_TEMPORARY, ERROR_SENDER_NO_MX, STRLEN(ERROR_SENDER_NO_MX), "DENIED_SENDER_NO_MX", 1, NULL, 0 }

#define REJECTION_RBL                           15
#define ERROR_RBL                               "Refused. Your IP address is listed in the RBL at "
#define REJECTION_DATA_RBL                      { REJECTION_RBL, REJECT_SEVERITY_PERMANENT, ERROR_RBL, STRLEN(ERROR_RBL), "DENIED_RBL_MATCH", 1, NULL, 0 }

#define REJECTION_RHSBL                         16
#define ERROR_RHSBL                             "Refused. Your domain name is listed in the RHSBL at "
#define REJECTION_DATA_RHSBL                    { REJECTION_RHSBL, REJECT_SEVERITY_PERMANENT, ERROR_RHSBL, STRLEN(ERROR_RHSBL), "DENIED_RHSBL_MATCH", 1, NULL, 0 }

#define REJECTION_SMTP_AUTH_FAILURE             17
#define ERROR_SMTP_AUTH_FAILURE                 "Refused. Authentication failed."
#define REJECTION_DATA_SMTP_AUTH_FAILURE        { REJECTION_SMTP_AUTH_FAILURE, REJECT_SEVERITY_AUTH_FAILURE, ERROR_SMTP_AUTH_FAILURE, STRLEN(ERROR_SMTP_AUTH_FAILURE), "FAILED_AUTH", 0, NULL, 0 }

#define REJECTION_SMTP_AUTH_UNKNOWN             18
#define ERROR_SMTP_AUTH_UNKNOWN                 "Refused. Unknown authentication method."
#define REJECTION_DATA_SMTP_AUTH_UNKNOWN        { REJECTION_SMTP_AUTH_UNKNOWN, REJECT_SEVERITY_AUTH_UNKNOWN, ERROR_SMTP_AUTH_UNKNOWN, STRLEN(ERROR_SMTP_AUTH_UNKNOWN), "UNKNOWN_AUTH", 0, NULL, 0 }

#define REJECTION_RELAYING_DENIED               19
#define ERROR_RELAYING_DENIED                   "Refused. Sending to remote addresses (relaying) is not allowed."
#define REJECTION_DATA_RELAYING_DENIED          { REJECTION_RELAYING_DENIED, REJECT_SEVERITY_PERMANENT, ERROR_RELAYING_DENIED, STRLEN(ERROR_RELAYING_DENIED), "DENIED_RELAYING", 1, NULL, 0 }

#define REJECTION_OTHER                         20
#define ERROR_OTHER                             ""
#define REJECTION_DATA_OTHER                    { REJECTION_OTHER, REJECT_SEVERITY_TEMPORARY, ERROR_OTHER, STRLEN(ERROR_OTHER), "DENIED_OTHER", 1, NULL, 0 }

#define REJECTION_ZERO_RECIPIENTS               21
#define ERROR_ZERO_RECIPIENTS                   "Refused. You must specify at least one valid recipient."
#define REJECTION_DATA_ZERO_RECIPIENTS          { REJECTION_ZERO_RECIPIENTS, REJECT_SEVERITY_PERMANENT, ERROR_ZERO_RECIPIENTS, STRLEN(ERROR_ZERO_RECIPIENTS), "DENIED_ZERO_RECIPIENTS", 0, NULL, 0 }

#define REJECTION_AUTH_REQUIRED                 22
#define ERROR_AUTH_REQUIRED                     "Refused. Authentication is required to send mail."
#define REJECTION_DATA_AUTH_REQUIRED            { REJECTION_AUTH_REQUIRED, REJECT_SEVERITY_PERMANENT, ERROR_AUTH_REQUIRED, STRLEN(ERROR_AUTH_REQUIRED), "DENIED_AUTH_REQUIRED", 1, NULL, 0 }

#define REJECTION_UNCONDITIONAL                 23
#define ERROR_UNCONDITIONAL                     "Refused. Mail is not being accepted."
#define REJECTION_DATA_UNCONDITIONAL            { REJECTION_UNCONDITIONAL, REJECT_SEVERITY_PERMANENT, ERROR_UNCONDITIONAL, STRLEN(ERROR_UNCONDITIONAL), "DENIED_REJECT_ALL", 1, NULL, 0 }

#define REJECTION_IDENTICAL_FROM_TO             24
#define ERROR_IDENTICAL_FROM_TO                 "Refused. Identical sender and recipient addresses are not allowed."
#define REJECTION_DATA_IDENTICAL_FROM_TO        { REJECTION_IDENTICAL_FROM_TO, REJECT_SEVERITY_PERMANENT, ERROR_IDENTICAL_FROM_TO, STRLEN(ERROR_IDENTICAL_FROM_TO), "DENIED_IDENTICAL_SENDER_RECIPIENT", 1, NULL, 0 }

#define REJECTION_HEADER_BLACKLISTED            25
#define ERROR_HEADER_BLACKLISTED                "Refused. Your message has been blocked due to its content."
#define REJECTION_DATA_HEADER_BLACKLISTED       { REJECTION_HEADER_BLACKLISTED, REJECT_SEVERITY_PERMANENT, ERROR_HEADER_BLACKLISTED, STRLEN(ERROR_HEADER_BLACKLISTED), "DENIED_HEADER_BLACKLISTED", 1, NULL, 0 }

#define REJECTION_INVALID_RECIPIENT             26
#define ERROR_INVALID_RECIPIENT                 "Refused. The recipient address does not exist."
#define REJECTION_DATA_INVALID_RECIPIENT        { REJECTION_INVALID_RECIPIENT, REJECT_SEVERITY_PERMANENT, ERROR_INVALID_RECIPIENT, STRLEN(ERROR_INVALID_RECIPIENT), "DENIED_INVALID_RECIPIENT", 1, NULL, 0 }

#define REJECTION_UNAVAILABLE_RECIPIENT         27
#define ERROR_UNAVAILABLE_RECIPIENT             "Refused. The recipient is not accepting mail right now."
#define REJECTION_DATA_UNAVAILABLE_RECIPIENT    { REJECTION_UNAVAILABLE_RECIPIENT, REJECT_SEVERITY_PERMANENT, ERROR_UNAVAILABLE_RECIPIENT, STRLEN(ERROR_UNAVAILABLE_RECIPIENT), "DENIED_UNAVAILABLE_RECIPIENT", 1, NULL, 0 }

#define REJECTION_SENDER_NOT_LOCAL              28
#define ERROR_SENDER_NOT_LOCAL                  "Refused. Mail for your sender domain is not hosted here."
#define REJECTION_DATA_SENDER_NOT_LOCAL         { REJECTION_SENDER_NOT_LOCAL, REJECT_SEVERITY_PERMANENT, ERROR_SENDER_NOT_LOCAL, STRLEN(ERROR_SENDER_NOT_LOCAL), "DENIED_SENDER_NOT_LOCAL", 1, NULL, 0 }

#define REJECTION_SENDER_NOT_AUTH               29
#define ERROR_SENDER_NOT_AUTH                   "Refused. Your sender address does not match your authentication username."
#define REJECTION_DATA_SENDER_NOT_AUTH          { REJECTION_SENDER_NOT_AUTH, REJECT_SEVERITY_PERMANENT, ERROR_SENDER_NOT_AUTH, STRLEN(ERROR_SENDER_NOT_AUTH), "DENIED_SENDER_NOT_AUTH", 1, NULL, 0 }

#define FAILURE_TLS                             30
#define ERROR_FAILURE_TLS                       "Failed to negotiate TLS connection."
#define FAILURE_DATA_TLS                        { FAILURE_TLS, REJECT_SEVERITY_TLS_FAILURE, ERROR_FAILURE_TLS, STRLEN(ERROR_FAILURE_TLS), "FAILED_TLS", 0, NULL, 0 }

#define REJECTION_DATA                  (struct rejection_data []){ \
                                        REJECTION_DATA_UNPARSEABLE, \
                                        REJECTION_DATA_RCPT_TO, \
                                        REJECTION_DATA_RCPT_TO_LOCAL, \
                                        REJECTION_DATA_GRAYLISTED, \
                                        REJECTION_DATA_RDNS_MISSING, \
                                        REJECTION_DATA_RDNS_RESOLVE, \
                                        REJECTION_DATA_IP_IN_NAME_CC, \
                                        REJECTION_DATA_IP_IN_NAME, \
                                        REJECTION_DATA_EARLYTALKER, \
                                        REJECTION_DATA_BLACKLIST_NAME, \
                                        REJECTION_DATA_BLACKLIST_IP, \
                                        REJECTION_DATA_TIMEOUT, \
                                        REJECTION_DATA_SENDER_BLACKLISTED, \
                                        REJECTION_DATA_RECIPIENT_BLACKLISTED, \
                                        REJECTION_DATA_SENDER_NO_MX, \
                                        REJECTION_DATA_RBL, \
                                        REJECTION_DATA_RHSBL, \
                                        REJECTION_DATA_SMTP_AUTH_FAILURE, \
                                        REJECTION_DATA_SMTP_AUTH_UNKNOWN, \
                                        REJECTION_DATA_RELAYING_DENIED, \
                                        REJECTION_DATA_OTHER, \
                                        REJECTION_DATA_ZERO_RECIPIENTS, \
                                        REJECTION_DATA_AUTH_REQUIRED, \
                                        REJECTION_DATA_UNCONDITIONAL, \
                                        REJECTION_DATA_IDENTICAL_FROM_TO, \
                                        REJECTION_DATA_HEADER_BLACKLISTED, \
                                        REJECTION_DATA_INVALID_RECIPIENT, \
                                        REJECTION_DATA_UNAVAILABLE_RECIPIENT, \
                                        REJECTION_DATA_SENDER_NOT_LOCAL, \
                                        REJECTION_DATA_SENDER_NOT_AUTH, \
                                        FAILURE_DATA_TLS \
                                        }

#define LOG_USE_CONFIG_TEST             0x01
#define LOG_USE_STDERR                  0x02
#define LOG_USE_SYSLOG                  0x04

/*
 * Log levels must be listed in ascending order from least output to most.
 *
 * NONE: No logging at all.
 *
 * CONFIG_TEST: Used only by config-test to print errors at the same level
 * as ERROR without the function names and line numbers.
 *
 * ERROR: Critical errors only, including low memory, network errors (not
 * including protocol errors), filesystem permission errors,
 * configuration-related errors and config-test errors
 *
 * INFO: Traffic logging, config-test success and info messages
 *
 * VERBOSE: Non-critical errors, including network errors caused by the remote
 * host, protocol errors, config-test status messages and child process error
 * messages
 *
 * DEBUG: High-level debugging output to show processing path
 *
 * EXCESSIVE: Low-level debugging output to processing progress and data
 */
#define LOG_LEVEL_NONE                  1
#define LOG_LEVEL_ERROR                 2
#define LOG_LEVEL_INFO                  3
#define LOG_LEVEL_VERBOSE               4
#define LOG_LEVEL_DEBUG                 5
#define LOG_LEVEL_EXCESSIVE             6

#define NIHDNS_LEVEL_NONE               1
#define NIHDNS_LEVEL_NORMAL             2
#define NIHDNS_LEVEL_AGGRESSIVE         3

/*
 * The values in NIHDNS_TYPE_ARRAY must correspond to the values in
 * CONFIG_DNS_TYPE_ARRAY.  The maximum index must not exceed
 * NUM_NIHDNS_TYPE.
 */
#define NUM_NIHDNS_TYPE                 8

#define NIHDNS_TYPE_A                   1
#define NIHDNS_TYPE_CNAME               5
#define NIHDNS_TYPE_MX                  15
#define NIHDNS_TYPE_NS                  2
#define NIHDNS_TYPE_PTR                 12
#define NIHDNS_TYPE_SOA                 6
#define NIHDNS_TYPE_TXT                 16
#define NIHDNS_TYPE_ANY                 255
#define NIHDNS_TYPE_ARRAY               (int []){ NIHDNS_TYPE_A, NIHDNS_TYPE_CNAME, NIHDNS_TYPE_MX, NIHDNS_TYPE_NS, NIHDNS_TYPE_PTR, NIHDNS_TYPE_SOA, NIHDNS_TYPE_TXT, NIHDNS_TYPE_ANY, 0 }

#define CONFIG_DNS_TYPE_A               0x01
#define CONFIG_DNS_TYPE_CNAME           0x02
#define CONFIG_DNS_TYPE_MX              0x04
#define CONFIG_DNS_TYPE_NS              0x08
#define CONFIG_DNS_TYPE_PTR             0x10
#define CONFIG_DNS_TYPE_SOA             0x20
#define CONFIG_DNS_TYPE_TXT             0x40
#define CONFIG_DNS_TYPE_ANY             0x80
#define CONFIG_DNS_TYPE_ARRAY           (int []){ CONFIG_DNS_TYPE_A, CONFIG_DNS_TYPE_CNAME, CONFIG_DNS_TYPE_MX, CONFIG_DNS_TYPE_NS, CONFIG_DNS_TYPE_PTR, CONFIG_DNS_TYPE_SOA, CONFIG_DNS_TYPE_TXT, CONFIG_DNS_TYPE_ANY, 0x00 }

#define NIHDNS_TCP_NONE                 1
#define NIHDNS_TCP_NORMAL               2

#define NIHDNS_SPOOF_ACCEPT_ALL         1
#define NIHDNS_SPOOF_ACCEPT_SAME_IP     2
#define NIHDNS_SPOOF_ACCEPT_SAME_PORT   3
#define NIHDNS_SPOOF_REJECT             4

#define NIHDNS_GETINT16(buffer)         (uint16_t)(((buffer)[0] << 8) | (buffer)[1])
#define NIHDNS_GETINT32(buffer)         (uint32_t)(((buffer)[0] << 24) | ((buffer)[1] << 16) | ((buffer)[2] << 8) | (buffer)[3])

#define NIHDNS_RESOLV_NAMESERVER        "nameserver"
#define NIHDNS_RESOLV_PORT              "port"
#define NIHDNS_RESOLV_TIMEOUT           "timeout"
#define NIHDNS_RESOLV_OPTIONS           "options"
#define NIHDNS_RESOLV_OPTION_TIMEOUT    "timeout:"

/*
 * The numeric order of these values is significant.  Any value greater than or
 * equal to RELAY_LEVEL_ALLOW_ALL will set the RELAYCLIENT environment variable
 * before qmail is started.
 */
#define RELAY_LEVEL_UNSET               1
#define RELAY_LEVEL_NO_RELAY            2
#define RELAY_LEVEL_NORMAL              3
#define RELAY_LEVEL_ALLOW_ALL           4

#define SPAMDYKE_USAGE(CURRENT_SETTINGS,LEVEL,FORMAT,DATA...) usage(CURRENT_SETTINGS,LEVEL,FORMAT,__func__,__FILE__,__LINE__,DATA);
#define SPAMDYKE_LOG_NONE(CURRENT_SETTINGS,FORMAT...)         ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_NONE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_NONE,1,FORMAT); })
#define SPAMDYKE_RELOG_NONE(CURRENT_SETTINGS,FORMAT...)       ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_NONE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_NONE,0,FORMAT); })
#define SPAMDYKE_LOG_ERROR(CURRENT_SETTINGS,FORMAT,DATA...)   ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_ERROR)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_ERROR,1,FORMAT,__func__,__FILE__,__LINE__,DATA); })
#define SPAMDYKE_RELOG_ERROR(CURRENT_SETTINGS,FORMAT,DATA...) ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_ERROR)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_ERROR,0,FORMAT,__func__,__FILE__,__LINE__,DATA); })
#define SPAMDYKE_LOG_INFO(CURRENT_SETTINGS,FORMAT...)         ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_INFO)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_INFO,1,FORMAT); })
#define SPAMDYKE_RELOG_INFO(CURRENT_SETTINGS,FORMAT...)       ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_INFO)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_INFO,0,FORMAT); })
#define SPAMDYKE_LOG_FILTER(CURRENT_SETTINGS,FORMAT...)       ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_VERBOSE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_VERBOSE,1,FORMAT); })
#define SPAMDYKE_RELOG_FILTER(CURRENT_SETTINGS,FORMAT...)     ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_VERBOSE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_VERBOSE,0,FORMAT); })
#define SPAMDYKE_LOG_VERBOSE(CURRENT_SETTINGS,FORMAT,DATA...) ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_VERBOSE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_VERBOSE,1,FORMAT,__func__,__FILE__,__LINE__,DATA); })
#define SPAMDYKE_RELOG_VERBOSE(CURRENT_SETTINGS,FORMAT,DATA...) ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_VERBOSE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_VERBOSE,0,FORMAT,__func__,__FILE__,__LINE__,DATA); })

#define SPAMDYKE_LOG_CONFIG_TEST_ERROR(CURRENT_SETTINGS,FORMAT...)      ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_ERROR)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_ERROR,1,FORMAT); })
#define SPAMDYKE_RELOG_CONFIG_TEST_ERROR(CURRENT_SETTINGS,FORMAT...)    ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_ERROR)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_ERROR,0,FORMAT); })
#define SPAMDYKE_LOG_CONFIG_TEST_INFO(CURRENT_SETTINGS,FORMAT...)       ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_INFO)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_INFO,1,FORMAT); })
#define SPAMDYKE_RELOG_CONFIG_TEST_INFO(CURRENT_SETTINGS,FORMAT...)     ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_INFO)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_INFO,0,FORMAT); })
#define SPAMDYKE_LOG_CONFIG_TEST_VERBOSE(CURRENT_SETTINGS,FORMAT...)    ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_VERBOSE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_VERBOSE,1,FORMAT); })
#define SPAMDYKE_RELOG_CONFIG_TEST_VERBOSE(CURRENT_SETTINGS,FORMAT...)  ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_VERBOSE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_VERBOSE,0,FORMAT); })

#ifndef WITHOUT_DEBUG_OUTPUT

#define SPAMDYKE_LOG_DEBUG(CURRENT_SETTINGS,FORMAT,DATA...) ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_DEBUG)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_DEBUG,1,FORMAT,__func__,__FILE__,__LINE__,DATA); })
#define SPAMDYKE_RELOG_DEBUG(CURRENT_SETTINGS,FORMAT,DATA...)       ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_DEBUG)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_DEBUG,0,FORMAT,__func__,__FILE__,__LINE__,DATA); })

#else /* WITHOUT_DEBUG_OUTPUT */

#define SPAMDYKE_LOG_DEBUG(CURRENT_SETTINGS,FORMAT...)        ({ })
#define SPAMDYKE_RELOG_DEBUG(CURRENT_SETTINGS,FORMAT...)      ({ })

#endif /* WITHOUT_DEBUG_OUTPUT */

#ifdef WITH_EXCESSIVE_OUTPUT

#define SPAMDYKE_LOG_EXCESSIVE(CURRENT_SETTINGS,FORMAT,DATA...)    ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_EXCESSIVE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_EXCESSIVE,1,FORMAT,__func__,__FILE__,__LINE__,DATA); })
#define SPAMDYKE_RELOG_EXCESSIVE(CURRENT_SETTINGS,FORMAT,DATA...)  ({ if (((CURRENT_SETTINGS) == NULL) || ((CURRENT_SETTINGS)->current_options == NULL) || ((CURRENT_SETTINGS)->current_options->log_dir != NULL) || ((CURRENT_SETTINGS)->current_options->log_level >= LOG_LEVEL_EXCESSIVE)) spamdyke_log(CURRENT_SETTINGS,LOG_LEVEL_EXCESSIVE,0,FORMAT,__func__,__FILE__,__LINE__,DATA); })

#else /* WITH_EXCESSIVE_OUTPUT */

#define SPAMDYKE_LOG_EXCESSIVE(CURRENT_SETTINGS,FORMAT...)    ({ })
#define SPAMDYKE_RELOG_EXCESSIVE(CURRENT_SETTINGS,FORMAT...)  ({ })

#endif /* WITH_EXCESSIVE_OUTPUT */

#define SYSLOG_IDENTIFIER               "spamdyke"

#define LOG_MISSING_DATA                "(unknown)"
#define LOG_EMPTY_DATA                  "(empty)"
#define LOG_MSG_TLS_NO_ERROR            "Operation failed but no error was reported by the SSL/TLS library"
#define LOG_MSG_TLS_ZERO_RETURN         "The connection was unexpectedly ended/closed"
#define LOG_MSG_TLS_RECALL              "The SSL/TLS library wants a function to be called again to complete after it's been recalled repeatedly. This shouldn't happen."
#define LOG_MSG_TLS_SYSCALL             "The operation failed due to an I/O error"
#define LOG_MSG_TLS_LIBRARY             "A protocol or library failure occurred"
#define LOG_MSG_TLS_EOF_FOUND           "Unexpected EOF found"

#define LOG_ERROR_GRAYLIST_FILE         "ERROR(%s()@%s:%d): cannot write to graylist file "
#define LOG_ERROR_MOVE_DESCRIPTORS      "ERROR(%s()@%s:%d): unable to move file descriptors: "
#define LOG_ERROR_FORK                  "ERROR(%s()@%s:%d): unable to fork: "
#define LOG_ERROR_PIPE                  "ERROR(%s()@%s:%d): unable to create pipe: "
#define LOG_ERROR_EXEC                  "ERROR(%s()@%s:%d): unable to execute child process "
#define LOG_ERROR_EXEC_FILE             "ERROR(%s()@%s:%d): unable to find executable "
#define LOG_ERROR_OPEN                  "ERROR(%s()@%s:%d): unable to open file "
#define LOG_ERROR_OPEN_KEYWORDS         "ERROR(%s()@%s:%d): unable to open keywords file "
#define LOG_ERROR_OPEN_SEARCH           "ERROR(%s()@%s:%d): unable to open file for searching "
#define LOG_ERROR_SOCKET_UDP            "ERROR(%s()@%s:%d): unable to create UDP socket: %s"
#define LOG_ERROR_SOCKET_TCP            "ERROR(%s()@%s:%d): unable to create TCP socket: %s"
#define LOG_ERROR_BIND                  "ERROR(%s()@%s:%d): unable to bind socket: %s"
#define LOG_ERROR_SETSOCKOPT            "ERROR(%s()@%s:%d): unable to set socket option: %s"
#define LOG_ERROR_SENDTO_INCOMPLETE     "ERROR(%s()@%s:%d): unable to send complete data packet, tried to send %d bytes, actually sent %d bytes"
#define LOG_ERROR_SENDTO                "ERROR(%s()@%s:%d): unable to send data packet, tried to send %d bytes: %s"
#define LOG_ERROR_STAT                  "ERROR(%s()@%s:%d): unable to stat() path "
#define LOG_ERROR_STAT_ERRNO            "ERROR(%s()@%s:%d): unable to stat() path %s: %s"
#define LOG_ERROR_MKDIR                 "ERROR(%s()@%s:%d): unable to create directory "
#define LOG_ERROR_OPEN_LOG              "ERROR(%s()@%s:%d): unable to open traffic log file "
#define LOG_ERROR_MOVE                  "ERROR(%s()@%s:%d): unable to move file "
#define LOG_ERROR_UNLINK                "ERROR(%s()@%s:%d): unable to remove file "
#define LOG_ERROR_MALLOC                "ERROR(%s()@%s:%d): out of memory - unable to allocate %lu bytes"
#define LOG_ERROR_TLS_CIPHER_LIST       "ERROR(%s()@%s:%d): unable to set SSL/TLS cipher list: "
#define LOG_ERROR_TLS_INIT              "ERROR(%s()@%s:%d): unable to initialize SSL/TLS library"
#define LOG_ERROR_TLS_CERTIFICATE       "ERROR(%s()@%s:%d): unable to load SSL/TLS certificate from file: "
#define LOG_ERROR_TLS_PRIVATEKEY        "ERROR(%s()@%s:%d): unable to load or decrypt SSL/TLS private key from file or certificate/key mismatch or incorrect password: "
#define LOG_ERROR_TLS_CERT_CHECK        "ERROR(%s()@%s:%d): incorrect SSL/TLS private key password or SSL/TLS certificate/privatekey mismatch"
#define LOG_ERROR_TLS_WRITE             "ERROR(%s()@%s:%d): unable to write to SSL/TLS stream"
#define LOG_ERROR_TLS_OPTIONS           "ERROR(%s()@%s:%d): unable to set SSL/TLS option: "
#define LOG_ERROR_TLS_DHPARAMS          "ERROR(%s()@%s:%d): unable to load SSL/TLS DH params from file: "
#define LOG_ERROR_TLS_SET_DHPARAMS      "ERROR(%s()@%s:%d): unable to set SSL/TLS DH params"
#define LOG_ERROR_OPEN_CONFIG           "ERROR(%s()@%s:%d): unable to open config file %s: %s"
#define LOG_ERROR_RESOLV_NS_BAD         "ERROR(%s()@%s:%d): invalid/unparsable nameserver found: %s"
#define LOG_ERROR_RESOLV_NS_PORT_BAD    "ERROR(%s()@%s:%d): invalid/unparsable nameserver port number found, defaulting to %d instead: %s"
#define LOG_ERROR_RESOLV_PORT_BAD       "ERROR(%s()@%s:%d): invalid/unparsable default port found in file %s on line %d: %s"
#define LOG_ERROR_RESOLV_GLOBAL_TIMEOUT_BAD     "ERROR(%s()@%s:%d): invalid/unparsable total timeout found in file %s on line %d: %s"
#define LOG_ERROR_RESOLV_QUERY_TIMEOUT_BAD      "ERROR(%s()@%s:%d): invalid/unparsable query timeout found in file %s on line %d: %s"
#define LOG_ERROR_RESOLV_QUERY_TIMEOUT_BAD_ENV  "ERROR(%s()@%s:%d): invalid/unparsable query timeout found in environment variable %s: %s"
#define LOG_ERROR_GETUSER               "ERROR(%s()@%s:%d): unable to find user with name or ID %s"
#define LOG_ERROR_GETUSER_ERRNO         "ERROR(%s()@%s:%d): unable to find user with name or ID %s: %s"
#define LOG_ERROR_SETUSER               "ERROR(%s()@%s:%d): unable to set current user to %s(%d): %s"
#define LOG_ERROR_GETGROUP              "ERROR(%s()@%s:%d): unable to find group with name or ID %s"
#define LOG_ERROR_SETGROUP              "ERROR(%s()@%s:%d): unable to set current group to %s(%d): %s"
#define LOG_ERROR_FPRINTF_LOG           "ERROR(%s()@%s:%d): unable to write to log file %s: "
#define LOG_ERROR_FPRINTF_BYTES         "ERROR(%s()@%s:%d): unable to write %d bytes to file %s: "
#define LOG_ERROR_OPTION_LIST_ORDER     "ERROR(%s()@%s:%d): option_list is out of order: %s comes before %s"
#define LOG_ERROR_OPTION_LIST_TYPE      "ERROR(%s()@%s:%d): option_list.value_type of option %s is an unexpected type; config_test_qmail_option() can't test it"
#define LOG_ERROR_SHORT_OPTION_CONFLICT "ERROR(%s()@%s:%d): short option %c is used by at least two options: %s and %s"
#define LOG_ERROR_SMTPS_SUPPORT         "ERROR(%s()@%s:%d): unable to start SMTPS because TLS support is not available or an SSL/TLS certificate is not available; closing connection"
#define LOG_ERROR_LATE_EARLYTALKER      "ERROR(%s()@%s:%d): earlytalker filter cannot be activated after the start of the connection -- ignoring configuration option"
#define LOG_ERROR_NONBLOCK_INPUT        "ERROR(%s()@%s:%d): unable to set input socket to nonblocking: "
#define LOG_ERROR_NONBLOCK_OUTPUT       "ERROR(%s()@%s:%d): unable to set output socket to nonblocking: "
#define LOG_ERROR_STATUS_INPUT          "ERROR(%s()@%s:%d): unable to get input socket nonblocking status: "
#define LOG_ERROR_STATUS_OUTPUT         "ERROR(%s()@%s:%d): unable to get output socket nonblocking status: "
#define LOG_ERROR_NONBLOCK_DNS_UDP      "ERROR(%s()@%s:%d): unable to set DNS UDP socket to nonblocking: "
#define LOG_ERROR_NONBLOCK_DNS_TCP      "ERROR(%s()@%s:%d): unable to set DNS TCP socket to nonblocking: "
#define LOG_ERROR_UDP_SPOOF             "ERROR(%s()@%s:%d): UDP packet received from an unexpected server, could be a DNS spoofing attempt: IP %s, port %d"
#define LOG_ERROR_CDB_EOF               "ERROR(%s()@%s:%d): unable to load data from CDB file %s: unexpected end of file"
#define LOG_ERROR_CDB_READ              "ERROR(%s()@%s:%d): unable to load data from CDB file %s: "
#define LOG_ERROR_CDB_SEEK              "ERROR(%s()@%s:%d): unable to find byte offset %ld within CDB file %s: "
#define LOG_ERROR_CDB_OPEN              "ERROR(%s()@%s:%d): unable to open CDB file %s: "
#define LOG_ERROR_VALIDATE_LOOP         "ERROR(%s()@%s:%d): recipient validation stuck in an infinite loop!"
#define LOG_ERROR_GETRLIMIT_AS          "ERROR(%s()@%s:%d): unable to find current limits for address space: %s"
#define LOG_ERROR_SETRLIMIT_AS          "ERROR(%s()@%s:%d): unable to reset limits for address space: %s"
#define LOG_ERROR_GETRLIMIT_DATA        "ERROR(%s()@%s:%d): unable to find current limits for data segment: %s"
#define LOG_ERROR_SETRLIMIT_DATA        "ERROR(%s()@%s:%d): unable to reset limits for data segment: %s"
#define LOG_ERROR_GETRLIMIT_STACK       "ERROR(%s()@%s:%d): unable to find current limits for stack size: %s"
#define LOG_ERROR_SETRLIMIT_STACK       "ERROR(%s()@%s:%d): unable to reset limits for stack size: %s"

#define LOG_VERBOSE_WRITE               "ERROR(%s()@%s:%d): unable to write %d bytes to file descriptor %d: "
#define LOG_VERBOSE_DNS_COMPRESSION     "ERROR(%s()@%s:%d): compressed DNS packet could not be decoded for %s; this could indicate a problem with the nameserver."
#define LOG_VERBOSE_DNS_RESPONSE        "ERROR(%s()@%s:%d): bad or invalid dns response to %s; this could indicate a problem with the name server."
#define LOG_VERBOSE_DNS_UNKNOWN_TYPE    "ERROR(%s()@%s:%d): DNS response for %s: expected type %s but received type %s"
#define LOG_VERBOSE_DNS_OVERSIZE        "ERROR(%s()@%s:%d): TCP DNS response for %s is %d total bytes, larger the maximum possible (%d bytes); something is very wrong here"
#define LOG_VERBOSE_DNS_CONNECT         "ERROR(%s()@%s:%d): unable to connect to DNS server %s:%d using TCP: "
#define LOG_VERBOSE_AUTH_FAILURE        "ERROR(%s()@%s:%d): authentication failure (bad username/password, vchkpw uses this to indicate SMTP access is not allowed): "
#define LOG_VERBOSE_AUTH_MISUSE         "ERROR(%s()@%s:%d): authentication misuse (no input given or no additional command path given, e.g. /bin/true): "
#define LOG_VERBOSE_AUTH_ERROR          "ERROR(%s()@%s:%d): authentication error (likely due to missing/unexecutable commands): "
#define LOG_VERBOSE_AUTH_VCHKPW_BAD_CHARS       "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate an unparsable email address): "
#define LOG_VERBOSE_AUTH_VCHKPW_UNKNOWN_USER    "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate an unknown username or authentication failure): "
#define LOG_VERBOSE_AUTH_VCHKPW_ENV_USER        "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate a failure to set the USER environment variable, possibly due to low memory): "
#define LOG_VERBOSE_AUTH_VCHKPW_ENV_HOME        "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate a failure to set the HOME environment variable, possibly due to low memory): "
#define LOG_VERBOSE_AUTH_VCHKPW_ENV_SHELL       "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate a failure to set the SHELL environment variable, possibly due to low memory): "
#define LOG_VERBOSE_AUTH_VCHKPW_ENV_VPOPUSER    "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate a failure to set the VPOPUSER environment variable, possibly due to low memory): "
#define LOG_VERBOSE_AUTH_VCHKPW_BAD_INPUT       "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate missing input on file descriptor 3): "
#define LOG_VERBOSE_AUTH_VCHKPW_NULL_USER       "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate an empty username): "
#define LOG_VERBOSE_AUTH_VCHKPW_NULL_PASSWORD   "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate an empty password): "
#define LOG_VERBOSE_AUTH_VCHKPW_HOME_DIR        "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate a failure to create a virtual user's home directory): "
#define LOG_VERBOSE_AUTH_VCHKPW_NO_PASSWORD     "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate a virtual user has no password): "
#define LOG_VERBOSE_AUTH_VCHKPW_UNKNOWN_SYSTEM_USER     "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate a failed username lookup in the system password file): "
#define LOG_VERBOSE_AUTH_VCHKPW_UNKNOWN_SYSTEM_SHADOW   "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate a failed username lookup in the system shadow file): "
#define LOG_VERBOSE_AUTH_VCHKPW_FAILURE_SYSTEM_USER     "ERROR(%s()@%s:%d): authentication error %d (vchkpw uses this to indicate a failed authentication attempt using the system password file): "
#define LOG_VERBOSE_AUTH_UNKNOWN        "ERROR(%s()@%s:%d): unknown authentication error code "
#define LOG_VERBOSE_AUTH_ABEND          "ERROR(%s()@%s:%d): authentication aborted abnormally: "
#define LOG_VERBOSE_COMMAND_ABEND       "ERROR(%s()@%s:%d): command aborted abnormally: "
#define LOG_VERBOSE_FILE_TOO_LONG       "ERROR(%s()@%s:%d): ignoring file content past line %d: "
#define LOG_VERBOSE_SMTPS_FAILURE       "ERROR(%s()@%s:%d): unable to start SMTPS due to a protocol failure; closing connection"
#define LOG_VERBOSE_REMOTEIP_LOCALHOST  "ERROR(%s()@%s:%d): remote IP address missing, found text: \"%s\", using IP address %s"
#define LOG_VERBOSE_REMOTEIP_TEXT       "ERROR(%s()@%s:%d): remote IP address missing, found text: \"%s\", searching DNS for IP address"
#define LOG_VERBOSE_MX_IP               "ERROR(%s()@%s:%d): found IP address in MX record where only are legal: %s domain: %s"
#define LOG_VERBOSE_DNS_OVERSIZE_QUERY  "ERROR(%s()@%s:%d): unable to create DNS query packet in %d bytes, name: %s type %s"
#define LOG_VERBOSE_BUFFER_OVERSIZE     "ERROR(%s()@%s:%d): unable to continue buffering message data, %d bytes of data retained, need %d bytes, maximum %d bytes allowed; emptying buffer"
#define LOG_VERBOSE_HEADER_TOO_LONG     "ERROR(%s()@%s:%d): header line too long, truncated at %d bytes: %.*s"
#define LOG_VERBOSE_UNPARSEABLE         "ERROR(%s()@%s:%d): unable to parse input: %.*s"
#define LOG_VERBOSE_TLS_ACCEPT          "ERROR(%s()@%s:%d): unable to start SSL/TLS connection"
#define LOG_VERBOSE_VALIDATE_OVERLENGTH "ERROR(%s()@%s:%d): unable to append domain and username to validation command, needed %d bytes of space, only %d available: %s"
#define LOG_VERBOSE_VALIDATE_EXIT       "ERROR(%s()@%s:%d): unknown exit code from validation command, code %d: %s"
#define LOG_VERBOSE_SETRLIMIT_AS        "ERROR(%s()@%s:%d): address space hard limit is less than infinity, could lead to unexplainable crashes: %ld"
#define LOG_VERBOSE_SETRLIMIT_DATA      "ERROR(%s()@%s:%d): data segment hard limit is less than infinity, could lead to unexplainable crashes: %ld"
#define LOG_VERBOSE_SETRLIMIT_STACK     "ERROR(%s()@%s:%d): stack size hard limit is less than infinity, could lead to unexplainable crashes: %ld"
#define LOG_VERBOSE_TLS_READ            "ERROR(%s()@%s:%d): unable to read from SSL/TLS stream"

#define LOG_FILTER_RDNS_MISSING         "FILTER_RDNS_MISSING ip: %s"
#define LOG_FILTER_IP_IN_RDNS_CC        "FILTER_IP_IN_CC_RDNS ip: %s rdns: %s"
#define LOG_FILTER_RDNS_WHITELIST       "FILTER_WHITELIST_NAME ip: %s rdns: %s entry: %s"
#define LOG_FILTER_RDNS_WHITELIST_FILE  "FILTER_WHITELIST_NAME ip: %s rdns: %s file: %s(%d)"
#define LOG_FILTER_RDNS_WHITELIST_DIR   "FILTER_WHITELIST_NAME ip: %s rdns: %s path: %s"
#define LOG_FILTER_RDNS_BLACKLIST       "FILTER_BLACKLIST_NAME ip: %s rdns: %s entry: %s"
#define LOG_FILTER_RDNS_BLACKLIST_FILE  "FILTER_BLACKLIST_NAME ip: %s rdns: %s file: %s(%d)"
#define LOG_FILTER_RDNS_BLACKLIST_DIR   "FILTER_BLACKLIST_NAME ip: %s rdns: %s path: %s"
#define LOG_FILTER_IP_WHITELIST         "FILTER_WHITELIST_IP ip: %s entry: %s"
#define LOG_FILTER_IP_WHITELIST_FILE    "FILTER_WHITELIST_IP ip: %s file: %s(%d)"
#define LOG_FILTER_IP_BLACKLIST         "FILTER_BLACKLIST_IP ip: %s entry: %s"
#define LOG_FILTER_IP_BLACKLIST_FILE    "FILTER_BLACKLIST_IP ip: %s file: %s(%d)"
#define LOG_FILTER_IP_IN_RDNS_BLACKLIST "FILTER_IP_IN_RDNS_BLACKLIST ip: %s rdns: %s keyword: %s file: (none)"
#define LOG_FILTER_IP_IN_RDNS_BLACKLIST_FILE    "FILTER_IP_IN_RDNS_BLACKLIST ip: %s rdns: %s keyword: %s file: %s(%d)"
#define LOG_FILTER_IP_IN_RDNS_WHITELIST "FILTER_IP_IN_RDNS_WHITELIST ip: %s rdns: %s keyword: %s file: (none)"
#define LOG_FILTER_IP_IN_RDNS_WHITELIST_FILE    "FILTER_IP_IN_RDNS_WHITELIST ip: %s rdns: %s keyword: %s file: %s(%d)"
#define LOG_FILTER_RDNS_RESOLVE         "FILTER_RDNS_RESOLVE ip: %s rdns: %s"
#define LOG_FILTER_DNS_RWL              "FILTER_RWL_MATCH ip: %s rwl: %s"
#define LOG_FILTER_DNS_RHSWL            "FILTER_RHSWL_MATCH domain: %s rhswl: %s"
#define LOG_FILTER_DNS_RBL              "FILTER_RBL_MATCH ip: %s rbl: %s"
#define LOG_FILTER_DNS_RHSBL            "FILTER_RHSBL_MATCH domain: %s rhsbl: %s"
#define LOG_FILTER_EARLYTALKER          "FILTER_EARLYTALKER delay: %d"
#define LOG_FILTER_SENDER_WHITELIST     "FILTER_SENDER_WHITELIST sender: %s entry: %s"
#define LOG_FILTER_SENDER_WHITELIST_FILE        "FILTER_SENDER_WHITELIST sender: %s file: %s(%d)"
#define LOG_FILTER_SENDER_RHSWL         "FILTER_RHSWL_MATCH domain: %s rhswl: %s"
#define LOG_FILTER_SENDER_BLACKLIST     "FILTER_SENDER_BLACKLIST sender: %s entry: %s"
#define LOG_FILTER_SENDER_BLACKLIST_FILE        "FILTER_SENDER_BLACKLIST sender: %s file: %s(%d)"
#define LOG_FILTER_SENDER_RHSBL         "FILTER_RHSBL_MATCH domain: %s rhsbl: %s"
#define LOG_FILTER_SMTP_AUTH            "FILTER_AUTH_REQUIRED"
#define LOG_FILTER_SENDER_MX            "FILTER_SENDER_NO_MX domain: %s"
#define LOG_FILTER_SENDER_LOCAL         "FILTER_SENDER_NOT_LOCAL domain: %s"
#define LOG_FILTER_SENDER_AUTH          "FILTER_SENDER_NOT_AUTH sender: %s username: %s"
#define LOG_FILTER_SENDER_AUTH_DOMAIN   "FILTER_SENDER_NOT_AUTH_DOMAIN domain: %s username: %s"
#define LOG_FILTER_RECIPIENT_WHITELIST  "FILTER_RECIPIENT_WHITELIST recipient: %s entry: %s"
#define LOG_FILTER_RECIPIENT_WHITELIST_FILE     "FILTER_RECIPIENT_WHITELIST recipient: %s file: %s(%d)"
#define LOG_FILTER_RECIPIENT_LOCAL      "FILTER_UNQUALIFIED_RECIPIENT recipient: %s"
#define LOG_FILTER_RECIPIENT_BLACKLIST  "FILTER_RECIPIENT_BLACKLIST recipient: %s entry: %s"
#define LOG_FILTER_RECIPIENT_BLACKLIST_FILE     "FILTER_RECIPIENT_BLACKLIST recipient: %s file: %s(%d)"
#define LOG_FILTER_RELAY                "FILTER_RELAYING"
#define LOG_FILTER_RECIPIENT_MAX        "FILTER_TOO_MANY_RECIPIENTS maximum: %d"
#define LOG_FILTER_GRAYLIST             "FILTER_GRAYLISTED sender: %s recipient: %s path: %s"
#define LOG_FILTER_ALLOW_ALL            "FILTER_ALLOW_ALL"
#define LOG_FILTER_REJECT_ALL           "FILTER_REJECT_ALL"
#define LOG_FILTER_OTHER_REJECTION      "FILTER_OTHER response: \"%.*s\""
#define LOG_FILTER_IDENTICAL_FROM_TO    "FILTER_IDENTICAL_SENDER_RECIPIENT sender: %s recipient: %s"
#define LOG_FILTER_INVALID_RECIPIENT    "FILTER_INVALID_RECIPIENT recipient: %s"
#define LOG_FILTER_UNAVAILABLE_RECIPIENT        "FILTER_UNAVAILABLE_RECIPIENT recipient: %s"
#define LOG_FILTER_HEADER_BLACKLIST     "FILTER_HEADER_BLACKLIST header: %s entry: %s"
#define LOG_FILTER_HEADER_BLACKLIST_FILE        "FILTER_HEADER_BLACKLIST header: %s file: %s(%d)"
#define LOG_FILTER_IP_RELAY             "FILTER_RELAY_IP ip: %s entry: %s"
#define LOG_FILTER_IP_RELAY_FILE        "FILTER_RELAY_IP ip: %s file: %s(%d)"
#define LOG_FILTER_RDNS_RELAY           "FILTER_RDNS_NAME ip: %s rdns: %s entry: %s"
#define LOG_FILTER_RDNS_RELAY_FILE      "FILTER_RDNS_NAME ip: %s rdns: %s file: %s(%d)"

#define LOG_DEBUG_AUTH_SUCCESS          "DEBUG(%s()@%s:%d): authentication successful: "
#define LOG_DEBUG_EXEC                  "DEBUG(%s()@%s:%d): executing command: %s"
#define LOG_DEBUG_EXEC_CHECKPASSWORD    "DEBUG(%s()@%s:%d): executing SMTP AUTH command %s for user: %s"
#define LOG_DEBUG_FILTER_RDNS_MISSING   "DEBUG(%s()@%s:%d): checking for missing rDNS; rdns: %s"
#define LOG_DEBUG_FILTER_IP_IN_RDNS_CC  "DEBUG(%s()@%s:%d): checking for IP in rDNS +country code; rdns: %s"
#define LOG_DEBUG_FILTER_RDNS_WHITELIST         "DEBUG(%s()@%s:%d): searching rDNS whitelist option(s); rdns: %s"
#define LOG_DEBUG_FILTER_RDNS_WHITELIST_FILE    "DEBUG(%s()@%s:%d): searching rDNS whitelist file(s); rdns: %s"
#define LOG_DEBUG_FILTER_RDNS_WHITELIST_DIR     "DEBUG(%s()@%s:%d): searching rDNS whitelist directory(ies); rdns: %s"
#define LOG_DEBUG_FILTER_RDNS_BLACKLIST         "DEBUG(%s()@%s:%d): searching rDNS blacklist option(s); rdns: %s"
#define LOG_DEBUG_FILTER_RDNS_BLACKLIST_FILE    "DEBUG(%s()@%s:%d): searching rDNS blacklist file(s); rdns: %s"
#define LOG_DEBUG_FILTER_RDNS_BLACKLIST_DIR     "DEBUG(%s()@%s:%d): searching rDNS blacklist directory(ies); rdns: %s"
#define LOG_DEBUG_FILTER_IP_WHITELIST   "DEBUG(%s()@%s:%d): searching IP whitelist file(s); ip: %s"
#define LOG_DEBUG_FILTER_IP_BLACKLIST   "DEBUG(%s()@%s:%d): searching IP blacklist file(s); ip: %s"
#define LOG_DEBUG_FILTER_IP_IN_RDNS_BLACKLIST   "DEBUG(%s()@%s:%d): checking for IP in rDNS +keyword(s) in blacklist file; ip: %s rdns: %s"
#define LOG_DEBUG_FILTER_IP_IN_RDNS_WHITELIST   "DEBUG(%s()@%s:%d): checking for IP in rDNS +keyword(s) in whitelist file; ip: %s rdns: %s"
#define LOG_DEBUG_FILTER_RDNS_RESOLVE   "DEBUG(%s()@%s:%d): checking rDNS resolution; rdns: %s"
#define LOG_DEBUG_FILTER_DNS_RWL        "DEBUG(%s()@%s:%d): checking DNS RWL(s); ip: %s"
#define LOG_DEBUG_FILTER_DNS_RHSWL      "DEBUG(%s()@%s:%d): checking rDNS RHSWL(s); rdns: %s"
#define LOG_DEBUG_FILTER_DNS_RBL        "DEBUG(%s()@%s:%d): checking DNS RBL(s); ip: %s"
#define LOG_DEBUG_FILTER_DNS_RHSBL      "DEBUG(%s()@%s:%d): checking rDNS RHSBL(s); rdns: %s"
#define LOG_DEBUG_FILTER_EARLYTALKER    "DEBUG(%s()@%s:%d): checking for earlytalker; delay: %d"
#define LOG_DEBUG_FILTER_SENDER_WHITELIST       "DEBUG(%s()@%s:%d): searching sender whitelist(s); sender: %s"
#define LOG_DEBUG_FILTER_SENDER_RHSWL           "DEBUG(%s()@%s:%d): checking sender domain RHSWL(s); domain: %s"
#define LOG_DEBUG_FILTER_SENDER_BLACKLIST       "DEBUG(%s()@%s:%d): searching sender blacklist(s); sender: %s"
#define LOG_DEBUG_FILTER_SENDER_RHSBL           "DEBUG(%s()@%s:%d): checking sender domain RHSBL(s); domain: %s"
#define LOG_DEBUG_FILTER_SMTP_AUTH              "DEBUG(%s()@%s:%d): checking for SMTP AUTH success; authenticated: %s"
#define LOG_DEBUG_FILTER_SENDER_MX              "DEBUG(%s()@%s:%d): checking for sender domain MX record; domain: %s"
#define LOG_DEBUG_FILTER_SENDER_LOCAL           "DEBUG(%s()@%s:%d): checking for sender domain in local domains; domain: %s"
#define LOG_DEBUG_FILTER_SENDER_AUTH            "DEBUG(%s()@%s:%d): checking for sender address in authenticated username; sender: %s, username: %s"
#define LOG_DEBUG_FILTER_SENDER_AUTH_DOMAIN     "DEBUG(%s()@%s:%d): checking for sender domain in authenticated username; domain: %s, username: %s"
#define LOG_DEBUG_FILTER_RECIPIENT_WHITELIST    "DEBUG(%s()@%s:%d): searching recipient whitelist(s); recipient: %s"
#define LOG_DEBUG_FILTER_RECIPIENT_BLACKLIST    "DEBUG(%s()@%s:%d): searching recipient blacklist(s); recipient: %s"
#define LOG_DEBUG_FILTER_RECIPIENT_MAX          "DEBUG(%s()@%s:%d): checking maximum recipients; maximum: %d current: %d"
#define LOG_DEBUG_FILTER_GRAYLIST               "DEBUG(%s()@%s:%d): checking graylist; recipient: %s sender: %s"
#define LOG_DEBUG_CONFIG_SEARCH         "DEBUG(%s()@%s:%d): searching for config file or dir at %s"
#define LOG_DEBUG_CONFIG_SEARCH_DIR     "DEBUG(%s()@%s:%d): searching for config dir at %s"
#define LOG_DEBUG_CONFIG_FILE           "DEBUG(%s()@%s:%d): reading configuration file: %s"
#define LOG_DEBUG_NO_SETUSER            "DEBUG(%s()@%s:%d): no UID switch requested, running as: %s (%d)"
#define LOG_DEBUG_IDLE_RESET            "DEBUG(%s()@%s:%d): child process closed; resetting idle timeout from 0 to %d"
#define LOG_DEBUG_REMOTEIP_DNS_FOUND    "DEBUG(%s()@%s:%d): found remote IP address using DNS: %s"
#define LOG_DEBUG_REMOTEIP_DNS_NOT_FOUND        "DEBUG(%s()@%s:%d): no remote IP address found using DNS, using default: %s"
#define LOG_DEBUG_REMOTEIP_ENV_UPDATED  "DEBUG(%s()@%s:%d): updated environment with remote IP address: %s"
#define LOG_DEBUG_FILTER_IDENTICAL_FROM_TO      "DEBUG(%s()@%s:%d): comparing addresses; sender: %s recipient: %s"
#define LOG_DEBUG_ADDRESS_CONTROL_CHAR  "DEBUG(%s()@%s:%d): found unprintable control character in address at position %d, ASCII code %d"
#define LOG_DEBUG_ADDRESS_EMPTY_USERNAME        "DEBUG(%s()@%s:%d): unable to parse username from address: %s"
#define LOG_DEBUG_ADDRESS_EMPTY_DOMAIN  "DEBUG(%s()@%s:%d): unable to parse domain from address: %s"
#define LOG_DEBUG_FIND_USERNAME         "DEBUG(%s()@%s:%d): found username: %s"
#define LOG_DEBUG_FIND_DOMAIN           "DEBUG(%s()@%s:%d): found domain: %s"
#define LOG_DEBUG_ADDRESS_ROUTING       "DEBUG(%s()@%s:%d): reparsing address from routing symbol at position %d: %s"
#define LOG_DEBUG_ADDRESS_USERNAME      "DEBUG(%s()@%s:%d): searching for username between positions %d and %d: %s"
#define LOG_DEBUG_ADDRESS_DOMAIN        "DEBUG(%s()@%s:%d): searching for domain between positions %d and %d: %s"
#define LOG_DEBUG_FILTER_HEADER_BLACKLIST       "DEBUG(%s()@%s:%d): searching header blacklist(s); header: %s"
#define LOG_DEBUG_CDB_KEY               "DEBUG(%s()@%s:%d): searching CDB file %s for %d byte key = %.*s, hash = %u, main index = %d, num_slots = %d, slot_num = %d"
#define LOG_DEBUG_TLS_CIPHER            "DEBUG(%s()@%s:%d): TLS/SSL connection established, using cipher %s, %d bits"
#define LOG_DEBUG_COMMAND_EXIT          "DEBUG(%s()@%s:%d): command exited with code %d: %s"
#define LOG_DEBUG_VALIDATE_OUTPUT       "DEBUG(%s()@%s:%d): output from validation command (%d bytes): %s\n%s"
#define LOG_DEBUG_SETRLIMIT_AS          "DEBUG(%s()@%s:%d): reset address space soft limit to infinity: please stop using the softlimit program"
#define LOG_DEBUG_SETRLIMIT_DATA        "DEBUG(%s()@%s:%d): reset data segment soft limit to infinity: please stop using the softlimit program"
#define LOG_DEBUG_SETRLIMIT_STACK       "DEBUG(%s()@%s:%d): reset stack size soft limit to infinity: please stop using the softlimit program"

#define LOG_DEBUGX_STRLEN_PREVIEW       30
#define LOG_DEBUGX_EXEC                 "EXCESSIVE(%s()@%s:%d): preparing to start child process: %s"
#define LOG_DEBUGX_DNS_QUERY            "EXCESSIVE(%s()@%s:%d): sending %d byte query (ID %d/%d) for %s(%s) to DNS server %s:%d (attempt %d)"
#define LOG_DEBUGX_DNS_RECEIVED         "EXCESSIVE(%s()@%s:%d): received DNS packet: %d bytes, ID %d/%d"
#define LOG_DEBUGX_DNS_RECEIVED_TYPE    "EXCESSIVE(%s()@%s:%d): received DNS response: %s, expected %s"
#define LOG_DEBUGX_DNS_TXT              "EXCESSIVE(%s()@%s:%d): found TXT record for %s: %.*s"
#define LOG_DEBUGX_DNS_A                "EXCESSIVE(%s()@%s:%d): found A record for %s: %d.%d.%d.%d"
#define LOG_DEBUGX_DNS_CNAME            "EXCESSIVE(%s()@%s:%d): found CNAME record for %s: %s"
#define LOG_DEBUGX_DNS_PTR              "EXCESSIVE(%s()@%s:%d): found PTR record for %s (%d bytes): %.*s"
#define LOG_DEBUGX_DNS_MX               "EXCESSIVE(%s()@%s:%d): found MX record for %s: %d %s"
#define LOG_DEBUGX_DNS_MX_LOCALHOST     "EXCESSIVE(%s()@%s:%d): rejecting MX record for %s: matches localhost address"
#define LOG_DEBUGX_DNS_NEGATIVE         "EXCESSIVE(%s()@%s:%d): found no records for %s"
#define LOG_DEBUGX_DOMAIN_DIR           "EXCESSIVE(%s()@%s:%d): searching for domain directory entry: %s"
#define LOG_DEBUGX_RESOLV_NS_LOAD       "EXCESSIVE(%s()@%s:%d): found nameserver at %s(%d): %s"
#define LOG_DEBUGX_RESOLV_NS_LOAD_DUPLICATE     "EXCESSIVE(%s()@%s:%d): discarded duplicate nameserver found at %s(%d): %s"
#define LOG_DEBUGX_RESOLV_NS            "EXCESSIVE(%s()@%s:%d): found nameserver: %s:%d"
#define LOG_DEBUGX_RESOLV_PORT          "EXCESSIVE(%s()@%s:%d): found resolver default port at %s(%d): %d"
#define LOG_DEBUGX_RESOLV_GLOBAL_TIMEOUT        "EXCESSIVE(%s()@%s:%d): found resolver global timeout at %s(%d): %d"
#define LOG_DEBUGX_RESOLV_QUERY_TIMEOUT "EXCESSIVE(%s()@%s:%d): found resolver query timeout at %s(%d): %d"
#define LOG_DEBUGX_RESOLV_QUERY_TIMEOUT_ENV     "EXCESSIVE(%s()@%s:%d): found resolver query timeout in environment variable %s: %d"
#define LOG_DEBUGX_RESOLV_NS_LOOPBACK   "EXCESSIVE(%s()@%s:%d): no nameservers found, using default server: %s:%d"
#define LOG_DEBUGX_RESOLV_IGNORED       "EXCESSIVE(%s()@%s:%d): ignored line at %s(%d): %s"
#define LOG_DEBUGX_SETUSER              "EXCESSIVE(%s()@%s:%d): set current user to %s(%d)."
#define LOG_DEBUGX_SETGROUP             "EXCESSIVE(%s()@%s:%d): set current group to %s(%d)."
#define LOG_DEBUGX_IP_IN_RDNS           "EXCESSIVE(%s()@%s:%d): searching for %.*s: %.*s"
#define LOG_DEBUGX_CHILD_EXIT_NORMAL    "EXCESSIVE(%s()@%s:%d): child process exited normally with return value %d"
#define LOG_DEBUGX_CHILD_EXIT_SIGNAL    "EXCESSIVE(%s()@%s:%d): child process exited/crashed due to receipt of signal %d"
#define LOG_DEBUGX_CHILD_EXIT_SIGNAL_CORE       "EXCESSIVE(%s()@%s:%d): child process exited/crashed due to receipt of signal %d and dumped core"
#define LOG_DEBUGX_CHILD_EXIT_STOPPED   "EXCESSIVE(%s()@%s:%d): child process is stopped by signal %d, probably by a debugger"
#define LOG_DEBUGX_CHILD_EXIT_STARTED   "EXCESSIVE(%s()@%s:%d): child process has resumed after being stopped, probably by a debugger"
#define LOG_DEBUGX_REMOTE_IP_ENV        "EXCESSIVE(%s()@%s:%d): found remote IP address environment variable %s: %s"
#define LOG_DEBUGX_REMOTE_IP_DEFAULT    "EXCESSIVE(%s()@%s:%d): remote IP address not found in an environment variable, using default: %s"
#define LOG_DEBUGX_GRAYLIST_DOMAIN_FOUND        "EXCESSIVE(%s()@%s:%d): found existing domain directory for graylisting: %s"
#define LOG_DEBUGX_GRAYLIST_DOMAIN_CREATE       "EXCESSIVE(%s()@%s:%d): created domain directory for graylisting: %s"
#define LOG_DEBUGX_GRAYLIST_RECIPIENT_CREATE    "EXCESSIVE(%s()@%s:%d): created recipient directory for graylisting: %s"
#define LOG_DEBUGX_GRAYLIST_SENDER_CREATE       "EXCESSIVE(%s()@%s:%d): created sender directory for graylisting: %s"
#define LOG_DEBUGX_GRAYLIST_MOVE        "EXCESSIVE(%s()@%s:%d): converted graylist directory from old structure to new structure: %s to %s"
#define LOG_DEBUGX_TEST_GRAYLIST_DOMAIN_DIR     "EXCESSIVE(%s()@%s:%d): found graylist recipient domain directory: %s"
#define LOG_DEBUGX_TEST_GRAYLIST_USER_DIR       "EXCESSIVE(%s()@%s:%d): found graylist recipient user directory: %s"
#define LOG_DEBUGX_TEST_GRAYLIST_SENDER_DIR     "EXCESSIVE(%s()@%s:%d): found graylist sender domain directory: %s"
#define LOG_DEBUGX_TEST_GRAYLIST_SENDER_FILE    "EXCESSIVE(%s()@%s:%d): found graylist sender user file: %s"
#define LOG_DEBUGX_OPEN_FILE            "EXCESSIVE(%s()@%s:%d): opened file for reading: %s"
#define LOG_DEBUGX_READ_LINE            "EXCESSIVE(%s()@%s:%d): read %d bytes from %s, line %d: %s"
#define LOG_DEBUGX_CHILD_READ           "EXCESSIVE(%s()@%s:%d): read %d bytes from child input file descriptor %d, buffer contains %d bytes, current position is %d: %.*s"
#define LOG_DEBUGX_CHILD_FD_EOF         "EXCESSIVE(%s()@%s:%d): child input file descriptor %d indicates EOF, buffer contains %d bytes, current position is %d"
#define LOG_DEBUGX_NETWORK_READ         "EXCESSIVE(%s()@%s:%d): read %d bytes from network input file descriptor %d, buffer contains %d bytes, current position is %d: %.*s"
#define LOG_DEBUGX_NETWORK_FD_EOF       "EXCESSIVE(%s()@%s:%d): network input file descriptor %d indicates EOF, buffer contains %d bytes, current position is %d"
#define LOG_DEBUGX_CHILD_IN_CLOSE       "EXCESSIVE(%s()@%s:%d): child input file descriptor %d closed"
#define LOG_DEBUGX_CHILD_OUT_CLOSE      "EXCESSIVE(%s()@%s:%d): child output file descriptor %d closed"
#define LOG_DEBUGX_SET_VALUE_FROM_FILE  "EXCESSIVE(%s()@%s:%d): set configuration option %s from file %s, line %d: %s"
#define LOG_DEBUGX_SMTP_AUTH_REPLACE    "EXCESSIVE(%s()@%s:%d): EHLO received; going to hide existing SMTP AUTH and add new SMTP AUTH"
#define LOG_DEBUGX_SMTP_AUTH_ADD        "EXCESSIVE(%s()@%s:%d): EHLO received; going to add SMTP AUTH"
#define LOG_DEBUGX_SMTP_AUTH_REMOVE     "EXCESSIVE(%s()@%s:%d): EHLO received; going to remove SMTP AUTH"
#define LOG_DEBUGX_TLS_ADD              "EXCESSIVE(%s()@%s:%d): EHLO received; going to add TLS"
#define LOG_DEBUGX_TLS_REMOVE           "EXCESSIVE(%s()@%s:%d): EHLO received; going to remove TLS"
#define LOG_DEBUGX_ENVIRONMENT_RELAY_FOUND      "EXCESSIVE(%s()@%s:%d): environment variable found to allow relaying: %s"
#define LOG_DEBUGX_ENVIRONMENT_RELAY_ADD        "EXCESSIVE(%s()@%s:%d): adding environment variable to allow relaying: %s"
#define LOG_DEBUGX_ENVIRONMENT_LOCAL_PORT_FOUND "EXCESSIVE(%s()@%s:%d): environment variable found for local port: %s"
#define LOG_DEBUGX_ENVIRONMENT_LOCAL_PORT_SET   "EXCESSIVE(%s()@%s:%d): setting environment variable for local port: %s"
#define LOG_DEBUGX_ENVIRONMENT_SMTPS_REMOVE     "EXCESSIVE(%s()@%s:%d): removing environment variable for SMTPS: %s"
#define LOG_DEBUGX_TLS_CERTIFICATE      "EXCESSIVE(%s()@%s:%d): loaded TLS certificate from file: %s"
#define LOG_DEBUGX_TLS_PRIVATEKEY_SEPARATE      "EXCESSIVE(%s()@%s:%d): loaded TLS private key from separate file: %s"
#define LOG_DEBUGX_TLS_PRIVATEKEY_CERTIFICATE   "EXCESSIVE(%s()@%s:%d): loaded TLS private key from certificate file: %s"
#define LOG_DEBUGX_TLS_CERT_CHECK               "EXCESSIVE(%s()@%s:%d): verified TLS certificate and private key"
#define LOG_DEBUGX_TLS_CIPHER_LIST      "EXCESSIVE(%s()@%s:%d): set TLS cipher list: %s"
#define LOG_DEBUGX_TLS_OPTIONS          "EXCESSIVE(%s()@%s:%d): set TLS option: %s"
#define LOG_DEBUGX_TLS_DHPARAMS         "EXCESSIVE(%s()@%s:%d): loaded TLS DH params from file: %s"
#define LOG_DEBUGX_TLS_SET_DHPARAMS     "EXCESSIVE(%s()@%s:%d): set TLS DH params"
#define LOG_DEBUGX_ENVIRONMENT_FOUND    "EXCESSIVE(%s()@%s:%d): found environment variable %.*s: %s"
#define LOG_DEBUGX_PATH_DEFAULT         "EXCESSIVE(%s()@%s:%d): no PATH found in environment, using default PATH: %s"
#define LOG_DEBUGX_PATH_SEARCH          "EXCESSIVE(%s()@%s:%d): searching along PATH: %s"
#define LOG_DEBUGX_ADDRESS_FOUND_QUOTE_OPEN     "EXCESSIVE(%s()@%s:%d): found opening quote in address at position %d: %s"
#define LOG_DEBUGX_ADDRESS_FOUND_QUOTE_CLOSE    "EXCESSIVE(%s()@%s:%d): found closing quote in address at position %d: %s"
#define LOG_DEBUGX_ADDRESS_NO_QUOTE_CLOSE       "EXCESSIVE(%s()@%s:%d): no closing quote found in address, assuming no quoted-string and resuming at position %d: %s"
#define LOG_DEBUGX_ADDRESS_ILLEGAL_CHAR         "EXCESSIVE(%s()@%s:%d): removing illegal character in address at position %d: %s"
#define LOG_DEBUGX_ADDRESS_ILLEGAL_DOT_START    "EXCESSIVE(%s()@%s:%d): removing illegal dot at start of domain: %s"
#define LOG_DEBUGX_ADDRESS_ILLEGAL_DOT_END      "EXCESSIVE(%s()@%s:%d): removing illegal dot at end of domain: %s"
#define LOG_DEBUGX_ADDRESS_ILLEGAL_DOT          "EXCESSIVE(%s()@%s:%d): ignoring illegal dot at start or end of username: %s"
#define LOG_DEBUGX_ADDRESS_FOUND_BRACKET_OPEN   "EXCESSIVE(%s()@%s:%d): found opening bracket in domain at position %d: %s"
#define LOG_DEBUGX_ADDRESS_FOUND_BRACKET_CLOSE  "EXCESSIVE(%s()@%s:%d): found closing bracket in domain at position %d: %s"
#define LOG_DEBUGX_ADDRESS_NO_BRACKET_CLOSE     "EXCESSIVE(%s()@%s:%d): no closing bracket found in domain, assuming no domain-literal and resuming at position %d: %s"
#define LOG_DEBUGX_ADDRESS_USERNAME     "EXCESSIVE(%s()@%s:%d): found username in address: %s"
#define LOG_DEBUGX_ADDRESS_DOMAIN       "EXCESSIVE(%s()@%s:%d): found domain in address: %s"
#define LOG_DEBUGX_TLS_DELAY            "EXCESSIVE(%s()@%s:%d): TLS operation did not complete, already waited %d seconds"
#define LOG_DEBUGX_DNS_TRUNCATED                "EXCESSIVE(%s()@%s:%d): DNS packet ID %d/%d truncated flag is set"
#define LOG_DEBUGX_DNS_QUERY_TCP        "EXCESSIVE(%s()@%s:%d): sending %d byte query (ID %d/%d) for %s(%s) via TCP"
#define LOG_DEBUGX_DNS_CONNECT          "EXCESSIVE(%s()@%s:%d): connecting to DNS server %s:%d via TCP"
#define LOG_DEBUGX_DNS_COUNTS           "EXCESSIVE(%s()@%s:%d): DNS packet ID %d/%d contains %d questions, %d answers"
#define LOG_DEBUGX_DNS_RECEIVED_TCP     "EXCESSIVE(%s()@%s:%d): received %d bytes via TCP, %d bytes so far in this response, expecting %d total"
#define LOG_DEBUGX_DNS_EMPTY_DATA       "EXCESSIVE(%s()@%s:%d): DNS data contains 0 bytes, ignoring response"
#define LOG_DEBUGX_DNS_TIMEOUT          "EXCESSIVE(%s()@%s:%d): waiting %d secs for DNS reply"
#define LOG_DEBUGX_AUTH_CRAMMD5_CHALLENGE       "EXCESSIVE(%s()@%s:%d): created CRAM-MD5 challenge text: %s"
#define LOG_DEBUGX_SOCKET_NONBLOCK      "EXCESSIVE(%s()@%s:%d): setting socket to nonblocking mode: %d"
#define LOG_DEBUGX_CLEAR_INPUT          "EXCESSIVE(%s()@%s:%d): discarding %d bytes of cached input"
#define LOG_DEBUGX_CLEAR_BUFFER         "EXCESSIVE(%s()@%s:%d): discarding %d bytes of buffered input"
#define LOG_DEBUGX_RETAIN_DATA          "EXCESSIVE(%s()@%s:%d): retaining %d new bytes of input, total %d bytes retained, max %d bytes allocated"
#define LOG_DEBUGX_RELEASE_DATA         "EXCESSIVE(%s()@%s:%d): sending %d bytes of buffered input: %.*s"
#define LOG_DEBUGX_COLLAPSE_WHITESPACE  "EXCESSIVE(%s()@%s:%d): collapsing whitespace from: (%d)%.*s to: (%d)%.*s"
#define LOG_DEBUGX_REMOTE_WRITE         "EXCESSIVE(%s()@%s:%d): wrote %d bytes to network file descriptor %d, buffer contained %d bytes: %.*s"
#define LOG_DEBUGX_CHILD_WRITE_CRLF     "EXCESSIVE(%s()@%s:%d): wrote %d bytes to child file descriptor %d, inserted CRLF, buffer contained %d bytes: %.*s"
#define LOG_DEBUGX_CHILD_WRITE          "EXCESSIVE(%s()@%s:%d): wrote %d bytes to child file descriptor %d, buffer contained %d bytes: %.*s"
#define LOG_DEBUGX_CDB_HASH                     "EXCESSIVE(%s()@%s:%d): looking for index entry; hash = %u, hash index = %u, main index offset = %lu, num slots = %d, slot number = %lu"
#define LOG_DEBUGX_CDB_SLOT             "EXCESSIVE(%s()@%s:%d): found slot; hash value = %u, data offset = %u"
#define LOG_DEBUGX_CDB_RECORD           "EXCESSIVE(%s()@%s:%d): found record header; key length = %lu, data length = %lu"
#define LOG_DEBUGX_CDB_KEY              "EXCESSIVE(%s()@%s:%d): loaded key, %d bytes: %.*s"
#define LOG_DEBUGX_CDB_DATA             "EXCESSIVE(%s()@%s:%d): loaded data, %d bytes: %s"
#define LOG_DEBUGX_CDB_DATA_NULL        "EXCESSIVE(%s()@%s:%d): found data but did not load: %d bytes"
#define LOG_DEBUGX_DNS_PREFERRED_TYPE   "EXCESSIVE(%s()@%s:%d): found preferred type: %s"
#define LOG_DEBUGX_DNS_POTENTIAL_ANSWER "EXCESSIVE(%s()@%s:%d): buffering potential answer of type %s, preferred type is %s"
#define LOG_DEBUGX_VALIDATE_STEP                "EXCESSIVE(%s()@%s:%d): current_step = %d, tmp_username = %.*s, tmp_domain = %s"
#define LOG_DEBUGX_RCPTHOSTS_FILE       "EXCESSIVE(%s()@%s:%d): found recipient domain %s in qmail-rcpthosts-file: %s"
#define LOG_DEBUGX_MORERCPTHOSTS_CDB    "EXCESSIVE(%s()@%s:%d): found recipient domain %s in qmail-morercpthosts-cdb: %s"
#define LOG_DEBUGX_VALIDATE_INVALID_RECIPIENT   "EXCESSIVE(%s()@%s:%d): invalid recipient: %s resolved username: %s"
#define LOG_DEBUGX_VALIDATE_UNAVAILABLE_RECIPIENT       "EXCESSIVE(%s()@%s:%d): unavailable recipient: %s resolved username: %s"
#define LOG_DEBUGX_FILE_STAT                    "EXCESSIVE(%s()@%s:%d): found file with mode %o (want %o), uid %d, gid %d: %s"
#define LOG_DEBUGX_FILE_STAT_FAIL               "EXCESSIVE(%s()@%s:%d): cannot find file %s: %s"
#define LOG_DEBUGX_CDB_VALIDATE_MAIN_INDEX      "EXCESSIVE(%s()@%s:%d): CDB main index %d: num_slots = %u, offset = %u"
#define LOG_DEBUGX_CDB_VALIDATE_SECONDARY_INDEX "EXCESSIVE(%s()@%s:%d): CDB main index %d, slot %d/%d: hash_value = %u, offset = %u"
#define LOG_DEBUGX_CDB_VALIDATE_RECORD_HEADER   "EXCESSIVE(%s()@%s:%d): CDB main index %d, slot %d/%d, hash_value = %u: key_length = %u, data_length = %u"
#define LOG_DEBUGX_CDB_VALIDATE_KEY             "EXCESSIVE(%s()@%s:%d): CDB main index %d, slot %d/%d, hash_value = %u, key_length = %u, key = %.*s: hash = %u"
#define LOG_DEBUGX_CONFIG_TEST_ERROR_SOURCE     "EXCESSIVE(%s()@%s:%d): config_test function for option %s returned an error result"
#define LOG_DEBUGX_CONFIG_ALIAS         "EXCESSIVE(%s()@%s:%d): option %s is an alias for %s: searching for %s"
#define LOG_DEBUGX_ADDITIONAL_DOMAIN    "EXCESSIVE(%s()@%s:%d): set additional domain text: %s"
#define LOG_DEBUGX_DNS_EXPAND_POINTER   "EXCESSIVE(%s()@%s:%d): expanding compressed DNS string - pointer at %d, goto %d"
#define LOG_DEBUGX_DNS_EXPAND_STRING    "EXCESSIVE(%s()@%s:%d): expanding compressed DNS string - string at %d, length %d, total length = %d"
#define LOG_DEBUGX_DNS_EXPAND_RESULT    "EXCESSIVE(%s()@%s:%d): expanded compressed DNS string - total %d bytes, returning %d: %s"
#define LOG_DEBUGX_LIMIT_AS             "EXCESSIVE(%s()@%s:%d): maximum address space is infinite"
#define LOG_DEBUGX_LIMIT_DATA           "EXCESSIVE(%s()@%s:%d): maximum data segment is infinite"
#define LOG_DEBUGX_LIMIT_STACK          "EXCESSIVE(%s()@%s:%d): maximum stack size is infinite"

#define ERROR_CONFIG_NO_COMMAND         "ERROR(%s()@%s:%d): Missing qmail-smtpd command"
#define ERROR_CONFIG_UNKNOWN_OPTION     "ERROR(%s()@%s:%d): Unknown or incomplete option: %s"
#define ERROR_CONFIG_UNKNOWN_OPTION_FILE        "ERROR(%s()@%s:%d): Unknown configuration file option in file %s on line %d: %s"
#define ERROR_CONFIG_BAD_VALUE          "ERROR(%s()@%s:%d): Bad or unparsable value for option %s: %s"
#define ERROR_CONFIG_BAD_INTEGER_RANGE  "ERROR(%s()@%s:%d): Illegal value for option %s: %s (must be between %d and %d)"
#define ERROR_CONFIG_BAD_NAME           "ERROR(%s()@%s:%d): Illegal value for option %s: %s (must be one of %s)"
#define ERROR_CONFIG_BAD_LENGTH         "ERROR(%s()@%s:%d): Value for option %s is %d characters, length limit is %d characters"
#define ERROR_CONFIG_ILLEGAL_OPTION_CMDLINE     "ERROR(%s()@%s:%d): Option not allowed on command line: %s"
#define ERROR_CONFIG_ILLEGAL_OPTION_FILE        "ERROR(%s()@%s:%d): Option not allowed in configuration file, found in file %s on line %d: %s"
#define ERROR_CONFIG_SYNTAX_OPTION_FILE         "ERROR(%s()@%s:%d): Bad syntax in configuration file %s on line %d: %.*s"

#define LOG_ACTION_LOG_IP                       -8
#define LOG_ACTION_LOG_RDNS                     -7
#define LOG_ACTION_TLS_PASSTHROUGH_START        -6
#define LOG_ACTION_AUTH_FAILURE                 -5
#define LOG_ACTION_AUTH_SUCCESS                 -4
#define LOG_ACTION_TLS_START                    -3
#define LOG_ACTION_TLS_END                      -2
#define LOG_ACTION_NONE                         -1
#define LOG_ACTION_REMOTE_FROM                  0
#define LOG_ACTION_CHILD_FROM                   1
#define LOG_ACTION_CHILD_FROM_DISCARDED         2
#define LOG_ACTION_FILTER_FROM                  3
#define LOG_ACTION_FILTER_TO                    4
#define LOG_ACTION_LOG_OUTPUT                   5
#define LOG_ACTION_CURRENT_CONFIG               6
#define LOG_ACTION_CURRENT_ENVIRONMENT          7
#define LOG_ACTION_PREFIX                       (char *[]){ "FROM REMOTE TO CHILD", "FROM CHILD TO REMOTE", "FROM CHILD, FILTERED", "FROM SPAMDYKE TO REMOTE", "FROM SPAMDYKE TO CHILD", "LOG OUTPUT", "CURRENT CONFIG", "CURRENT ENVIRONMENT" }
#define LOG_ACTION_PREFIX_TLS_SPAMDYKE          " TLS"
#define LOG_ACTION_PREFIX_TLS_PASSTHROUGH       " TLS_PASSTHROUGH"
#define LOG_ACTION_PREFIX_AUTH                  " AUTH:"
#define LOG_MESSAGE_TLS_PASSTHROUGH_START       "TLS passthrough started"
#define LOG_MESSAGE_TLS_START                   "TLS negotiated and started"
#define LOG_MESSAGE_TLS_END                     "TLS ended and closed"
#define LOG_MESSAGE_AUTH_SUCCESS                "Authentication successful"
#define LOG_MESSAGE_AUTH_FAILURE                "Authentication failed: "
#define LOG_MESSAGE_REMOTE_IP                   "Remote IP = "
#define LOG_MESSAGE_RDNS_NAME                   "Remote rDNS = "

#define LOG_MESSAGE_DNS_SEPARATOR       ", "
#define LOG_MESSAGE_DNS_TYPE_A          "A"
#define LOG_MESSAGE_DNS_TYPE_CNAME      "CNAME"
#define LOG_MESSAGE_DNS_TYPE_MX         "MX"
#define LOG_MESSAGE_DNS_TYPE_NS         "NS"
#define LOG_MESSAGE_DNS_TYPE_PTR        "PTR"
#define LOG_MESSAGE_DNS_TYPE_SOA        "SOA"
#define LOG_MESSAGE_DNS_TYPE_TXT        "TXT"

#define CONFIG_TEST_OPTION_NAME_BINARY  "binary-check"

#define CONFIG_TEST_ENVIRONMENT_LOCAL_PORT      "TCPLOCALPORT=25"
#define CONFIG_TEST_ENVIRONMENT_REMOTE_IP               { ENVIRONMENT_REMOTE_IP_TCPSERVER ENVIRONMENT_DELIMITER_STRING LOCALHOST_IP, ENVIRONMENT_REMOTE_IP_OLD_INETD ENVIRONMENT_DELIMITER_STRING LOCALHOST_IP, NULL }
#define CONFIG_TEST_STRLEN_ENVIRONMENT_REMOTE_IP        { STRLEN(ENVIRONMENT_REMOTE_IP_TCPSERVER ENVIRONMENT_DELIMITER_STRING LOCALHOST_IP), STRLEN(ENVIRONMENT_REMOTE_IP_OLD_INETD ENVIRONMENT_DELIMITER_STRING LOCALHOST_IP), -1 }
#define CONFIG_TEST_ENVIRONMENT_REMOTE_NAME     "TCPREMOTEHOST=localhost"

#define CONFIG_TEST_BAD_CONFIG_DIR_EXEC "ERROR(%s): Impossible test condition (DIR_EXEC). Please report this error to the author."
#define CONFIG_TEST_BAD_CONFIG_CMD_READ "ERROR(%s): Impossible test condition (CMD_READ). Please report this error to the author."
#define CONFIG_TEST_BAD_CONFIG_CMD_WRITE        "ERROR(%s): Impossible test condition (CMD_WRITE). Please report this error to the author."
#define CONFIG_TEST_BAD_CONFIG_CMD_READ_WRITE   "ERROR(%s): Impossible test condition (CMD_READ_WRITE). Please report this error to the author."

#define CONFIG_TEST_START               "Testing configuration..."
#define CONFIG_TEST_SUCCESS             "SUCCESS: Tests complete. No errors detected."
#define CONFIG_TEST_ERROR               "ERROR: Tests complete. Errors detected."
#define CONFIG_TEST_MISSING             "ERROR: config-test support was not included when spamdyke was compiled."

#define CONFIG_TEST_SUCCESS_UID         "SUCCESS: Running tests as user %s(%d), group %s(%d)."
#define CONFIG_TEST_WARNING_UID         "WARNING: Running tests as user %s(%d), group %s(%d). Is this the same user and group the mail server uses?"
#define CONFIG_TEST_ERROR_UID           "WARNING: Running tests as superuser %s(%d), group %s(%d). These test results may not be valid if the mail server runs as another user."

#define CONFIG_TEST_SUCCESS_SETUID      "SUCCESS: spamdyke binary (%s) is not owned by root and/or is not marked setuid."
#define CONFIG_TEST_ERROR_SETUID        "ERROR: spamdyke binary (%s) is owned by root and marked setuid. This is not necessary or recommended; it could be a security hole if exploitable bugs exist in spamdyke."
#define CONFIG_TEST_ERROR_SETUID_STAT   "ERROR: Unable to stat() spamdyke binary (%s) to scan permissions: %s"
#define CONFIG_TEST_ERROR_SETUID_SEARCH "ERROR: Unable to find spamdyke binary (%s) in the current path."
#define CONFIG_TEST_ERROR_SETUID_FILENAME       "ERROR: Name of current binary is unknown. This condition should be impossible."

#define CONFIG_TEST_START_FILE_READ     "INFO(%s): Testing file read: %s"
#define CONFIG_TEST_SUCCESS_FILE_READ   "SUCCESS(%s): Opened for reading: %s"
#define CONFIG_TEST_ERROR_FILE_READ     "ERROR(%s): Failed to open for reading: %s: %s"
#define CONFIG_TEST_START_FILE_WRITE    "INFO(%s): Testing file write: %s"
#define CONFIG_TEST_SUCCESS_FILE_WRITE  "SUCCESS(%s): Opened for writing: %s"
#define CONFIG_TEST_ERROR_FILE_WRITE    "ERROR(%s): Failed to open for writing: %s: %s"
#define CONFIG_TEST_START_FILE_READ_WRITE       "INFO(%s): Testing file reading and writing: %s"
#define CONFIG_TEST_SUCCESS_FILE_READ_WRITE     "SUCCESS(%s): Opened for reading and writing: %s"
#define CONFIG_TEST_ERROR_FILE_READ_WRITE       "ERROR(%s): Failed to open for reading and writing: %s: %s"
#define CONFIG_TEST_START_EXECUTE       "INFO(%s): Testing executable: %s"
#define CONFIG_TEST_SUCCESS_EXECUTE     "SUCCESS(%s): File is executable: %s"
#define CONFIG_TEST_ERROR_EXECUTE       "ERROR(%s): File is not executable: %s: %s"
#define CONFIG_TEST_START_DIR_READ      "INFO(%s): Testing directory tree and all files for reading: %s"
#define CONFIG_TEST_SUCCESS_DIR_READ    "SUCCESS(%s): Directory tree and all files are readable: %s"
#define CONFIG_TEST_ERROR_DIR_READ      "ERROR(%s): Portions of directory tree and/or some files are not readable: %s: %s"
#define CONFIG_TEST_START_DIR_WRITE     "INFO(%s): Testing directory for writing: %s"
#define CONFIG_TEST_SUCCESS_DIR_WRITE   "SUCCESS(%s): Created and deleted file in directory: %s"
#define CONFIG_TEST_ERROR_DIR_WRITE     "ERROR(%s): Failed to create file in directory: %s: %s"
#define CONFIG_TEST_ERROR_DIR_WRITE_DELETE      "ERROR(%s): Failed to delete test file in directory: %s: %s"
#define CONFIG_TEST_ERROR_FILE_OVERLENGTH       "ERROR(%s): File is too long; all content after line %d will be ignored: %s"

#define CONFIG_TEST_FILE_LINE_RECOMMENDATION    100
#define CONFIG_TEST_ERROR_FILE_OVERRECOMMENDATION       "WARNING(%s): File length is inefficient; consider using a directory structure instead: %s"

#define CONFIG_TEST_START_TLS           "INFO(%s): Testing TLS by initializing SSL/TLS library with certificate and key"
#define CONFIG_TEST_START_TLS_PRIVATEKEY        "INFO(%s): Testing TLS private key file for reading: %s"
#define CONFIG_TEST_START_TLS_DHPARAMS  "INFO(%s): Testing TLS DH params file for reading: %s"
#define CONFIG_TEST_SUCCESS_TLS         "SUCCESS(%s): Certificate and key loaded; SSL/TLS library successfully initialized"
#define CONFIG_TEST_ERROR_TLS_CERT_DISABLED             "ERROR(%s): TLS support is not compiled into this executable but a TLS certificate file was given anyway: %s"
#define CONFIG_TEST_ERROR_TLS_PRIVATEKEY_DISABLED       "ERROR(%s): TLS support is not compiled into this executable but a TLS private key file was given anyway: %s"
#define CONFIG_TEST_ERROR_TLS_PASSWORD_DISABLED         "ERROR(%s): TLS support is not compiled into this executable but a TLS private key password was given anyway."
#define CONFIG_TEST_ERROR_TLS_DHPARAMS_DISABLED         "ERROR(%s): TLS support is not compiled into this executable but a TLS DH params file was given anyway: %s"

#define CONFIG_TEST_SMTPAUTH_START      "INFO(%s): Examining authentication command: %s"
#define CONFIG_TEST_SMTPAUTH_OWNER_WARN "WARNING(%s): Authentication command is not owned by root. Some require being setuid root to read system passwords: %s: owned by %s(%d)"
#define CONFIG_TEST_SMTPAUTH_SETUID_WARN        "WARNING(%s): Authentication command is owned by root but not setuid. Some require being setuid root to read system passwords: %s"
#define CONFIG_TEST_SMTPAUTH_RUN_PLAIN  "INFO(%s): Running authentication command with unencrypted input: %s"
#define CONFIG_TEST_SUCCESS_SMTPAUTH_PLAIN      "SUCCESS(%s): Authentication succeeded with unencrypted input: %s"
#define CONFIG_TEST_FAILURE_SMTPAUTH_PLAIN      "ERROR(%s): Authentication failed with unencrypted input: %s"
#define CONFIG_TEST_SMTPAUTH_RUN_ENCRYPTED      "INFO(%s): Running authentication command with encrypted input: %s"
#define CONFIG_TEST_SUCCESS_SMTPAUTH_ENCRYPTED  "SUCCESS(%s): Authentication succeeded with encrypted input: %s"
#define CONFIG_TEST_FAILURE_SMTPAUTH_ENCRYPTED  "ERROR(%s): Authentication failed with encrypted input: %s"
#define CONFIG_TEST_SMTPAUTH_SUGGEST_ENCRYPTED  "INFO: One or more authentication commands support encrypted input; change the value of \"smtp-auth-level\" to \"%s\" or \"%s\" instead of \"%s\""
#define CONFIG_TEST_SMTPAUTH_SUGGEST_PLAIN      "INFO: No authentication commands support encrypted input; change the value of \"smtp-auth-level\" to \"%s\" or \"%s\" instead of \"%s\""
#define CONFIG_TEST_SMTPAUTH_UNUSED     "WARNING: None of the \"smtp-auth-command\" options will be used; \"smtp-auth-level\" is too low. Use a value of at least \"%s\""

#define CONFIG_TEST_TYPE_IFIFO          "FIFO (i.e. a named pipe)"
#define CONFIG_TEST_TYPE_IFCHR          "character device (e.g. a serial port)"
#define CONFIG_TEST_TYPE_IFDIR          "directory"
#define CONFIG_TEST_TYPE_IFBLK          "block device (e.g. a hard disk)"
#define CONFIG_TEST_TYPE_IFREG          "regular file"
#define CONFIG_TEST_TYPE_IFLNK          "symbolic link"
#define CONFIG_TEST_TYPE_IFSOCK         "socket"
#define CONFIG_TEST_TYPE_IFWHT          "whiteout"
#define CONFIG_TEST_TYPE_UNKNOWN        "filesystem entry of unknown type"

#define CONFIG_TEST_MSG_NO_EXEC         "File is not executable by the current user."

#define CONFIG_TEST_START_GRAYLIST      "INFO(%s): Testing graylist directory: %s"
#define CONFIG_TEST_SUCCESS_GRAYLIST    "SUCCESS(%s): Graylist directory tests succeeded: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_NONE_OPTIONS "ERROR(%s): The \"graylist-level\" option is \"none\" but other graylist options were given. They will all be ignored."
#define CONFIG_TEST_ERROR_GRAYLIST_TOP_DIR      "ERROR(%s): Unable to read graylist directory %s: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_TOP_OTHER    "ERROR(%s): Found %s in graylist directory where only domain directories should be: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_TOP_ORPHAN   "INFO(%s): Found domain directory for a domain that is not in the list of local domains; the domain directory will not be used: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_DOMAIN_DIR   "ERROR(%s): Unable to read graylist domain directory %s: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_DOMAIN_OTHER "ERROR(%s): Found %s in graylist domain directory where only user directories should be: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_USER_DIR     "ERROR(%s): Unable to read graylist user directory %s: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_USER_OTHER   "ERROR(%s): Found %s in graylist user directory where only user directories should be: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_SENDER_DIR   "ERROR(%s): Unable to read graylist sender directory %s: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_SENDER_OTHER "ERROR(%s): Found %s in graylist sender directory where only sender files should be: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_DOMAIN_MISSING       "INFO(%s): Local domain has no domain directory; no graylisting will take place for the domain: %s"
#define CONFIG_TEST_ERROR_GRAYLIST_DOMAIN_CREATE        "INFO(%s): Local domain has no domain directory; spamdyke will create the directory when needed: %s"

#define CONFIG_TEST_START_CONFIGURATION_DIR     "INFO(%s): Testing configuration directory: %s"
#define CONFIG_TEST_SUCCESS_CONFIGURATION_DIR   "SUCCESS(%s): Configuration directory tests succeeded: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_TOP_OTHER   "ERROR(%s): Path to configuration directory is not a directory, it is a %s: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_DUPLICATE_DIR       "ERROR(%s): Found multiple configuration subdirectories named \"%s\" in the same path. This directory structure is invalid and will be ignored. Full path: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_DUPLICATE_USERNAME  "ERROR(%s): Found multiple configuration subdirectories named \"%s\" in the same path that are decendents of a \"%s\" directory. This directory structure is invalid and will be ignored. Full path: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_MISPLACED_USERNAME  "ERROR(%s): Found a configuration subdirectory named \"%s\" that is not a decendent of a \"%s\" directory or a \"%s\" directory. This directory structure is invalid and will be ignored. Full path: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_IP_BAD_OCTET        "ERROR(%s): Found a directory named \"%s\" that is not an integer between 0 and 255 but is a decendent of a \"%s\" directory. This directory structure is invalid and will be ignored. Full path: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_IP_TOO_DEEP "ERROR(%s): Found too many decendents of a \"%s\" directory (IP addresses can only have 4 octets). This directory structure is invalid and will be ignored. Full path: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_USERNAME_TOO_DEEP   "ERROR(%s): Found too many decendents of a \"%s\" directory (email addresses can only have 1 username). This directory structure is invalid and will be ignored. Full path: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_MISSING_DATA        "ERROR(%s): Found a \"%s\" directory as an immediate decendent of a \"%s\" directory. This directory structure is invalid and will be ignored. Full path: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_BAD_FILENAME        "ERROR(%s): Found a file named \"%s\", which should only be used for directory names. This file name is invalid and will be ignored. Full path: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_OPENDIR     "ERROR(%s): Unable to read configuration directory %s: %s"
#define CONFIG_TEST_ERROR_CONFIGURATION_DIR_BAD_TYPE    "ERROR(%s): Found an unexpected object (%s) in a directory structure that should only contain files and directories. This object is invalid and will be ignored. Full path: %s"

#define CONFIG_TEST_START_RDNS_DIR      "INFO(%s): Testing rDNS directory: %s"
#define CONFIG_TEST_SUCCESS_RDNS_DIR    "SUCCESS(%s): rDNS directory tests succeeded: %s"
#define CONFIG_TEST_ERROR_RDNS_LETTER_DIR       "ERROR(%s): rDNS directory name is longer than one character: %s"
#define CONFIG_TEST_ERROR_RDNS_LETTER_MISMATCH  "ERROR(%s): rDNS directory name does not start with the same single character as its parent: %s"
#define CONFIG_TEST_ERROR_RDNS_FQDN_MISMATCH    "ERROR(%s): rDNS entry does not match domain name %s: %s"
#define CONFIG_TEST_ERROR_RDNS_NO_FILES "ERROR(%s): rDNS directory contains no files: %s"
#define CONFIG_TEST_ERROR_RDNS_NO_FOLDERS       "ERROR(%s): rDNS directory contains no subdirectories: %s"
#define CONFIG_TEST_ERROR_RDNS_OPENDIR  "ERROR(%s): Unable to read rDNS directory: %s"
#define CONFIG_TEST_ERROR_RDNS_NON_DIR  "ERROR(%s): Found %s in rDNS directory where only directories should be: %s"
#define CONFIG_TEST_ERROR_RDNS_NON_FILE "ERROR(%s): Found %s in rDNS directory where only files should be: %s"

#define CONFIG_TEST_PATCH_SUCCESS_CONTINUATION  "\r\n250-"
#define CONFIG_TEST_PATCH_SUCCESS_END           "\r\n250 "
#define CONFIG_TEST_PATCH_TLS                   "starttls\r\n"
#define CONFIG_TEST_PATCH_SMTP_AUTH             "auth "
#define CONFIG_TEST_PATCH_EXPECT_GREETING       "220 "
#define CONFIG_TEST_PATCH_EXPECT_EHLO           "\r\n250 "
#define CONFIG_TEST_PATCH_SEND_EHLO             "EHLO localhost\r\n"
#define CONFIG_TEST_PATCH_SEND_QUIT             "QUIT\r\n"
#define CONFIG_TEST_PATCH_SCRIPT                { \
                                                  { ES_TYPE_EXPECT, CONFIG_TEST_PATCH_EXPECT_GREETING, STRLEN(CONFIG_TEST_PATCH_EXPECT_GREETING) }, \
                                                  { ES_TYPE_SEND, CONFIG_TEST_PATCH_SEND_EHLO, STRLEN(CONFIG_TEST_PATCH_SEND_EHLO) }, \
                                                  { ES_TYPE_EXPECT, CONFIG_TEST_PATCH_EXPECT_EHLO, STRLEN(CONFIG_TEST_PATCH_EXPECT_EHLO) }, \
                                                  { ES_TYPE_SEND, CONFIG_TEST_PATCH_SEND_QUIT, STRLEN(CONFIG_TEST_PATCH_SEND_QUIT) }, \
                                                  { ES_TYPE_NONE, NULL, 0 } \
                                                }
#define CONFIG_TEST_PATCH_RUN                   "INFO: Running command to test capabilities: %s"
#define CONFIG_TEST_ERROR_PATCH_NO_OUTPUT       "ERROR: Command returned no output: %s"
#define CONFIG_TEST_SUCCESS_PATCH_TLS           "SUCCESS: %s appears to offer TLS support but spamdyke will intercept and decrypt the TLS traffic so all of its filters can operate."
#define CONFIG_TEST_SUCCESS_PATCH_TLS_NO_TLS    "ERROR: %s appears to offer TLS support. The \"tls-type\" and \"tls-certificate-file\" options are being used but TLS support is not compiled into spamdyke. Unless it is recompiled with TLS support, the following spamdyke features will not function during TLS deliveries: graylisting, sender whitelisting, sender blacklisting, sender domain MX checking, DNS RHSBL checking for sender domains, recipient whitelisting, recipient blacklisting, limited number of recipients and full logging."
#define CONFIG_TEST_SUCCESS_PATCH_TLS_FLAG      "WARNING: %s appears to offer TLS support but spamdyke cannot use all of its filters unless it can intercept and decrypt the TLS traffic. Please use (or change) the \"tls-type\" and \"tls-certificate-file\" options. Otherwise, the following spamdyke features will not function during TLS deliveries: graylisting, sender whitelisting, sender blacklisting, sender domain MX checking, DNS RHSBL checking for sender domains, recipient whitelisting, recipient blacklisting, limited number of recipients and full logging."
#define CONFIG_TEST_SUCCESS_PATCH_TLS_FLAG_NO_TLS       "WARNING: %s appears to offer TLS support but spamdyke was not compiled with TLS support. spamdyke cannot use all of its filters unless it can intercept and decrypt the TLS traffic. Please recompile spamdyke with TLS support and use (or change) the \"tls-type\" and \"tls-certificate-file\" options. Unless it is recompiled with TLS support, the following spamdyke features will not function during TLS deliveries: graylisting, sender whitelisting, sender blacklisting, sender domain MX checking, DNS RHSBL checking for sender domains, recipient whitelisting, recipient blacklisting, limited number of recipients and full logging."
#define CONFIG_TEST_ERROR_PATCH_TLS             "SUCCESS: %s does not appear to offer TLS support. spamdyke will offer, intercept and decrypt TLS traffic."
#define CONFIG_TEST_ERROR_PATCH_TLS_NO_TLS      "ERROR: %s does not appear to offer TLS support and spamdyke was not compiled with TLS support. The \"tls-type\" and \"tls-certificate-file\" options will be ignored. Please recompile spamdyke with TLS support."
#define CONFIG_TEST_ERROR_PATCH_TLS_FLAG        "WARNING: %s does not appear to offer TLS support. Please use (or change) the \"tls-type\" and \"tls-certificate-file\" options so spamdyke can offer, intercept or decrypt TLS traffic."
#define CONFIG_TEST_ERROR_PATCH_TLS_FLAG_NO_TLS "ERROR: %s does not appear to offer TLS support and spamdyke was not compiled with TLS support. The \"tls-type\" and \"tls-certificate-file\" options will be ignored. Please recompile spamdyke with TLS support."
#define CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_NONE        "SUCCESS: %s appears to offer SMTP AUTH support but spamdyke will block authentication attempts."
#define CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_NONE_FLAG   "ERROR: %s appears to offer SMTP AUTH support but spamdyke will block authentication attempts. The \"smtp-auth-command\" option was given but will be ignored."
#define CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_OBSERVE     "SUCCESS: %s appears to offer SMTP AUTH support. spamdyke will observe any authentication and trust its response."
#define CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_OBSERVE_FLAG        "ERROR: %s appears to offer SMTP AUTH support. spamdyke will observe any authentication and trust its response. The \"smtp-auth-command\" option was given but will be ignored."
#define CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_DEMAND      "SUCCESS: %s appears to offer SMTP AUTH support. spamdyke will observe any authentication and trust its response. spamdyke will offer authentication if %s does not."
#define CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_DEMAND_FLAG "ERROR: %s appears to offer SMTP AUTH support. spamdyke will observe any authentication and trust its response but spamdyke cannot process responses itself because one or more of the following options was not given: \"qmail-rcpthosts-file\", \"qmail-morercpthosts-cdb\" or \"smtp-auth-command\""
#define CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_ALWAYS      "SUCCESS: %s appears to offer SMTP AUTH support but spamdyke will offer and process all authentication itself."
#define CONFIG_TEST_SUCCESS_PATCH_SMTP_AUTH_ALWAYS_FLAG "ERROR: %s appears to offer SMTP AUTH support but spamdyke cannot offer and process authentication itself because one of the following options was not given: \"qmail-rcpthosts-file\", \"qmail-morercpthosts-cdb\" or \"smtp-auth-command\""
#define CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_NONE  "SUCCESS: %s does not appear to offer SMTP AUTH support. spamdyke will block authentication attempts."
#define CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_NONE_FLAG     "ERROR: %s does not appear to offer SMTP AUTH support. spamdyke will block authentication attempts. The \"smtp-auth-command\" option was given but will be ignored."
#define CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_OBSERVE       "SUCCESS: %s does not appear to offer SMTP AUTH support. spamdyke will observe any authentication and trust its response (although that appears unlikely to happen)."
#define CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_OBSERVE_FLAG  "ERROR: %s does not appear to offer SMTP AUTH support. spamdyke will observe any authentication and trust its response (although that appears unlikely to happen). The \"smtp-auth-command\" option was given but will be ignored."
#define CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_DEMAND        "SUCCESS: %s does not appear to offer SMTP AUTH support. spamdyke will offer and process authentication."
#define CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_DEMAND_FLAG   "ERROR: %s does not appear to offer SMTP AUTH support. spamdyke cannot offer and process authentication because one of the following options was not given: \"qmail-rcpthosts-file\", \"qmail-morercpthosts-cdb\" or \"smtp-auth-command\""
#define CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_ALWAYS        "SUCCESS: %s does not appear to offer SMTP AUTH support. spamdyke will offer and process all authentication itself."
#define CONFIG_TEST_ERROR_PATCH_SMTP_AUTH_ALWAYS_FLAG   "ERROR: %s does not appear to offer SMTP AUTH support but spamdyke cannot offer and process authentication itself because one of the following options was not given: \"qmail-rcpthosts-file\", \"qmail-morercpthosts-cdb\" or \"smtp-auth-command\""

#define CONFIG_TEST_OPTION_ARRAY_LIMIT          25
#define CONFIG_TEST_ERROR_OPTION_ARRAY          "WARNING: %s is used %d times; to increase efficiency, consider moving those values to a file instead."

#define CONFIG_TEST_ERROR_RELAY_NO_RELAY_MISSING_LOCAL  "ERROR(%s): The \"relay-level\" option is \"block-all\" but no acceptable domains were given with \"qmail-rcpthosts-file\" or \"qmail-morercpthosts-cdb\". The relaying filter will not function correctly (messages to local recipients may be rejected)."
#define CONFIG_TEST_ERROR_RELAY_NORMAL_MISSING_LOCAL    "ERROR(%s): The \"relay-level\" option is \"normal\" but no acceptable domains were given with \"qmail-rcpthosts-file\" or \"qmail-morercpthosts-cdb\". The relaying filter will not function correctly (messages to local recipients may be rejected)."

#define CONFIG_TEST_START_CDB                   "INFO(%s): Testing CDB file: %s"
#define CONFIG_TEST_SUCCESS_CDB                 "SUCCESS(%s): CDB file tests succeeded: %s"
#define CONFIG_TEST_FAILURE_CDB                 "ERROR(%s): CDB file tests failed, is it possible %s is not a CDB file but instead the text file used as the source to create a CDB file?"
#define CONFIG_TEST_ERROR_CDB_MISSING           "ERROR(%s): Unable to find CDB file %s: %s"
#define CONFIG_TEST_ERROR_CDB_TOO_SMALL         "ERROR(%s): CDB file %s is too small to contain index records, file is %d bytes, must be minimum %d bytes"
#define CONFIG_TEST_ERROR_CDB_READ              "ERROR(%s): Unable to open CDB file %s for reading: %s"
#define CONFIG_TEST_ERROR_CDB_READ_ERROR        "ERROR(%s): Unable to read %d bytes from %s, error occurred"
#define CONFIG_TEST_ERROR_CDB_MAIN_OFFSET       "ERROR(%s): Record offset within main index slot %d is beyond the end of the file: %u bytes, file is %lu bytes"
#define CONFIG_TEST_ERROR_CDB_SEEK_ERROR        "ERROR(%s): Unable to seek to offset %d within %s: %s"
#define CONFIG_TEST_ERROR_CDB_SECONDARY_OFFSET  "ERROR(%s): Record offset within main index %d, slot %d is beyond the end of the file: %u bytes, file is %lu bytes"
#define CONFIG_TEST_ERROR_CDB_RECORD_LENGTH     "ERROR(%s): Record length (from main index %d, slot %d) is beyond the end of the file: %u bytes, file is %lu bytes"
#define CONFIG_TEST_ERROR_CDB_HASH_MISMATCH     "ERROR(%s): Expected hash value %u does not match calculated hash value %u from loaded key %.*s (%u bytes) in file %s"
#define CONFIG_TEST_ERROR_CDB_MAIN_MISMATCH     "ERROR(%s): Main index %d does not match calculated main index %d (hash %u) from loaded key %.*s in file %s"
#define CONFIG_TEST_WARNING_CDB_KEY_OVERLENGTH  "WARNING(%s): Key length (from main index %d, slot %d) is too big to read into memory, skipping hash verification: %d bytes, maximum %d bytes"
#define CONFIG_TEST_WARNING_CDB_EMPTY           "WARNING(%s): CDB file %s contains no records. Is this really correct?"

#define CONFIG_TEST_QMAIL_NONDEFAULT            "WARNING: %s has been changed from the default value of %s, this is not recommended and could lead to errors during recipient validation."

#define CONFIG_TYPE_NONE                        -3
/* Used for options that trigger an action rather than setting a variable */
#define CONFIG_TYPE_ACTION_ONCE                 -2
#define CONFIG_TYPE_ACTION_MULTIPLE             -1
/* True/false option */
#define CONFIG_TYPE_BOOLEAN                     0
/* Numeric option */
#define CONFIG_TYPE_INTEGER                     1
/* Text values ONLY - option values (like blacklist entries) should use OPTION_* */
#define CONFIG_TYPE_STRING_SINGLETON            2
#define CONFIG_TYPE_STRING_ARRAY                3
/* A single filename, can only be set once */
#define CONFIG_TYPE_FILE_SINGLETON              4
/* A single filename that has an alternate directory option ("-file" vs "-dir") */
#define CONFIG_TYPE_FILE_NOT_DIR_SINGLETON      5
/* Multiple filenames, stored in an array */
#define CONFIG_TYPE_FILE_ARRAY                  6
/* Multiple filenames that have an alternate directory option ("-file" vs "-dir") */
#define CONFIG_TYPE_FILE_NOT_DIR_ARRAY          7
/* A single directory, can only be set once */
#define CONFIG_TYPE_DIR_SINGLETON               8
/* Multiple directories, stored in an array */
#define CONFIG_TYPE_DIR_ARRAY                   9
/* A single command path with arguments, can only be set once */
#define CONFIG_TYPE_COMMAND_SINGLETON           10
/* Multiple command paths with arguments, stored in an array */
#define CONFIG_TYPE_COMMAND_ARRAY               11
/*
 * A text value that is matched against an array of values and stored as an
 * integer
 */
#define CONFIG_TYPE_NAME_ONCE                   12
/*
 * Multiple text values that are matched against an array of values to find
 * an integer value, then bitwise-ORed together
 */
#define CONFIG_TYPE_NAME_MULTIPLE               13
/*
 * A single string value that usually has an alternate file or directory option,
 * can only be set once
 */
#define CONFIG_TYPE_OPTION_SINGLETON            14
/*
 * A string value that usually has an alternate file or directory, stored in an
 * array
 */
#define CONFIG_TYPE_OPTION_ARRAY                15
/* An option that is just an alias for another option (i.e. an alternate name) */
#define CONFIG_TYPE_ALIAS                       16

#define CONFIG_ACCESS_NONE                      0
#define CONFIG_ACCESS_READ_ONLY                 1
#define CONFIG_ACCESS_WRITE_ONLY                2
#define CONFIG_ACCESS_READ_WRITE                3
#define CONFIG_ACCESS_EXECUTE                   4

#define CONFIG_LOCATION_MASK_ERRORS_CRITICAL    0x0F
#define CONFIG_LOCATION_MASK_ERRORS_FORGIVEN    0xF0

#define CONFIG_LOCATION_MASK_BASE_OPTIONS       0x0F
#define CONFIG_LOCATION_MASK_COPY_OPTIONS       0xF0

#define CONFIG_LOCATION_CMDLINE                 0x01
#define CONFIG_LOCATION_GLOBAL_FILE             0x02
#define CONFIG_LOCATION_DIR                     0x10

#define CONFIG_SET_ACTION(CMD)                  ({ int action(struct filter_settings *current_settings, int current_return_value, char *input_value, struct previous_action *history) { CMD; return(current_return_value); } &action; })
#define CONFIG_ACTION(CMD)                      ({ int action(struct filter_settings *current_settings, int current_return_value) { CMD; return(current_return_value); } &action; })
#define CONFIG_ACCESSOR_INTEGER(MEMBER)         ({ int *access_integer(struct option_set *current_options) { return(&current_options->MEMBER); } &access_integer; })
#define CONFIG_ACCESSOR_STRING(MEMBER)          ({ char **access_string(struct option_set *current_options, int current_options_only) { return(&current_options->MEMBER); } &access_string; })
#define CONFIG_ACCESSOR_STRING_ARRAY(MEMBER)    ({ char ***access_string_array(struct option_set *current_options, int current_options_only) { return(&current_options->MEMBER); } &access_string_array; })

#define ES_TYPE_NONE                            0
#define ES_TYPE_SEND                            1
#define ES_TYPE_EXPECT                          2

struct nihdns_header
  {
  uint16_t id;
  uint16_t bitfields;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
  };

struct expect_send
  {
  int type;
  char *data;
  int strlen_data;
  };

struct filter_settings;

struct previous_action
  {
  char *data;
  int count;
  struct previous_action *prev;
  };

struct option_set
  {
  /* These member variables are not accessible from option_list in
   * prepare_settings() -- they must be initialized/cleared explicitly
   * in init_option_set().
   */
  struct filter_settings *container;
  int prev_filter_action;
  int filter_action;
  int filter_action_locked;
  int filter_grace;

  /*
   * Some rejections are transient and some are permanent.  Transient rejections
   * affect the current command (e.g. rejecting a specific recipient) without
   * affecting the entire connection.
   *
   * The *_buf variables are used when a rejection needs modification before
   * being sent to the client.  set_rejection() will copy an entry from the
   * REJECTION_DATA array into the *_buf variable, make changes as needed, then
   * assign rejection or transient_rejection to point to the *_buf variable.
   * Otherwise, rejection or transient_rejection will point directly to the
   * element in REJECTION_DATA.  In no case should rejection or
   * transient_rejection ever be free()d.
   */
  struct rejection_data *rejection;
  struct rejection_data *transient_rejection;
  struct rejection_data rejection_buf;
  struct rejection_data transient_rejection_buf;
  char reject_message_buf[MAX_BUF + 1];
  char short_reject_message_buf[MAX_BUF + 1];
  char reject_reason_buf[MAX_BUF + 1];
  char transient_reject_message_buf[MAX_BUF + 1];
  char transient_short_reject_message_buf[MAX_BUF + 1];
  char transient_reject_reason_buf[MAX_BUF + 1];

  /* prev_rejection should never be free()d.  It always points to a rejection
   * (see above) or NULL.
   */
  struct rejection_data *prev_rejection;

  int strlen_policy_location;

  struct sockaddr_in nihdns_primary_server_data[MAX_NIHDNS_SERVERS + 1];
  struct sockaddr_in nihdns_secondary_server_data[MAX_NIHDNS_SERVERS + 1];

  /*
   * All members of this struct must be accessable from option_list in
   * prepare_settings() so they can be free()d by looping through that
   * structure at the end of prepare_settings() and free_current_options().
   */
  char *rejection_text[sizeof(REJECTION_DATA) / sizeof(struct rejection_data)];
  char *run_user;
  char **config_file;
  int filter_level;

  char *local_server_name;
  char *local_server_name_file;
  char *local_server_name_command;

  char **graylist_dir;
  int graylist_min_secs;
  int graylist_max_secs;
  int max_rcpt_to;
  int log_target;
  int log_level;
  int relay_level;
  char *policy_location;
  char *log_dir;
  char **blacklist_sender;
  char **blacklist_sender_file;
  char **whitelist_sender;
  char **whitelist_sender_file;
  char **blacklist_recipient;
  char **blacklist_recipient_file;
  char **whitelist_recipient;
  char **whitelist_recipient_file;
  int configuration_dir_search;
  char **configuration_dir;

  char **blacklist_rdns_keyword;
  char **blacklist_rdns_keyword_file;
  char **whitelist_rdns_keyword;
  char **whitelist_rdns_keyword_file;
  char **blacklist_rdns;
  char **blacklist_rdns_file;
  char **blacklist_rdns_dir;
  char **blacklist_ip;
  char **blacklist_ip_file;
  char **whitelist_rdns;
  char **whitelist_rdns_file;
  char **whitelist_rdns_dir;
  char **whitelist_ip;
  char **whitelist_ip_file;
  char **dnsrwl_fqdn;
  char **dnsrwl_fqdn_file;
  char **dnsrbl_fqdn;
  char **dnsrbl_fqdn_file;
  char **rhswl_fqdn;
  char **rhswl_fqdn_file;
  char **rhsbl_fqdn;
  char **rhsbl_fqdn_file;
  char **graylist_exception_ip;
  char **graylist_exception_ip_file;
  char **graylist_exception_rdns;
  char **graylist_exception_rdns_file;
  char **graylist_exception_rdns_dir;
  char **blacklist_header;
  char **blacklist_header_file;
  char **smtp_auth_command;
  int smtp_auth_level;

  char **relay_ip;
  char **relay_ip_file;
  char **relay_rdns;
  char **relay_rdns_file;

  int graylist_level;
  int check_ip_in_rdns_cc;
  int check_earlytalker;
  int check_rdns_exist;
  int check_rdns_resolve;

  int reject_sender;
  int reject_recipient;

  int timeout_connection;
  int timeout_command;

  int nihdns_level;
  int nihdns_tcp;
  int nihdns_spoof;
  char **nihdns_primary_server_list;
  char **nihdns_secondary_server_list;
  int nihdns_attempts_primary;
  int nihdns_attempts_total;
  int nihdns_timeout_total_secs_parameter;
  int nihdns_timeout_total_secs_system;
  char **nihdns_resolv_conf;
  int nihdns_query_type_a;
  int nihdns_query_type_mx;
  int nihdns_query_type_ptr;
  int nihdns_query_type_rbl;

  int tls_level;
  char *tls_certificate_file;
  char *tls_privatekey_file;
  int strlen_tls_privatekey_password;
  char *tls_privatekey_password;
  char *tls_privatekey_password_file;
  char *tls_cipher_list;
  char *tls_dhparams_file;

  char **qmail_rcpthosts_file;
  char **qmail_morercpthosts_cdb;
  char **recipient_validation_command;

  char *test_smtp_auth_username;
  char *test_smtp_auth_password;
  };

struct integer_string
  {
  int *integers;
  char **strings;
  };

struct spamdyke_option
  {
  int value_type;
  int access_type;
  int location;
  struct option getopt_option;
  union
    {
    int integer_value;
    char *string_value;
    } default_value;
  union
    {
    int integer_value;
    char *string_value;
    } missing_value;
  union
    {
    int *(*get_integer)(struct option_set *);
    char **(*get_string)(struct option_set *, int);
    char ***(*get_string_array)(struct option_set *, int);
    } getter;
  union
    {
    int max_strlen;
    struct
      {
      int minimum;
      int maximum;
      } integer_range;
    struct integer_string string_list;
    } validity;
  int set_consequence;
  int set_grace;
  int (*test_function)(struct filter_settings *, struct spamdyke_option *);
  int (*additional_set_actions)(struct filter_settings *, int, char *, struct previous_action *);
  int (*additional_actions)(struct filter_settings *, int);
  char *help_argument;
  char *help_text;
  int value_set;
  };

struct filter_settings
  {
  struct option_set base_options;
  struct option_set *current_options;

  struct spamdyke_option *option_list;
  int num_options;
  struct option *long_options;
  char short_options[MAX_BUF + 1];
  struct spamdyke_option **option_lookup;
  int max_short_code;

  /* original_environment must always be the envp value passed to main() */
  char **original_environment;
  /*
   * current_environment may contain values from original_environment but must
   * never contain static strings that cannot be free()d.
   */
  char **current_environment;

  char server_name[MAX_BUF + 1];
  int strlen_server_name;
  char *server_ip;
  char tmp_server_ip[MAX_BUF + 1];
  int strlen_server_ip;
  int ip_in_server_name;

  int allow_relay;
  char additional_domain_text[MAX_BUF + 1];
  int inside_data;
  int inside_header;

  char sender_username[MAX_ADDRESS + 1];
  char sender_domain[MAX_ADDRESS + 1];
  char recipient_username[MAX_ADDRESS + 1];
  char recipient_domain[MAX_ADDRESS + 1];
  char **allowed_recipients;
  int num_recipients;

  char configuration_path[MAX_PATH + 1];

  char **child_argv;

  int smtp_auth_state;
  int smtp_auth_type;
  int smtp_auth_origin;
  char smtp_auth_challenge[MAX_BUF + 1];
  char smtp_auth_response[MAX_BUF + 1];
  char smtp_auth_username[MAX_BUF + 1];
  char *smtp_auth_domain;

  time_t connection_start;
  time_t command_start;

  int tls_state;

  char reconstructed_header[MAX_NETWORK_BUF + STRLEN(STR_CRLF) + 1];
  int strlen_reconstructed_header;
  char *buf_retain;
  int strlen_buf_retain;
  int max_buf_retain;
  char **blacklist_header;
  char **blacklist_header_file;

#ifdef HAVE_LIBSSL

  SSL_CTX *tls_context;
  SSL *tls_session;

#endif /* HAVE_LIBSSL */

  };

#endif /* SPAMDYKE_H */
