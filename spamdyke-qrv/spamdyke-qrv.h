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

#ifndef SPAMDYKE_QRV_H
#define SPAMDYKE_QRV_H

#ifdef WITH_EXCESSIVE_OUTPUT

#define VERSION_EXCESSIVE               "+EXCESSIVE"

#else /* WITH_EXCESSIVE_OUTPUT */

#define VERSION_EXCESSIVE               ""

#endif /* WITH_EXCESSIVE_OUTPUT */

#ifdef WITH_VPOPMAIL_SUPPORT

#define VERSION_VPOPMAIL                "+VPOPMAIL"

#else /* WITH_VPOPMAIL_SUPPORT */

#define VERSION_VPOPMAIL                ""

#endif /* WITH_VPOPMAIL_SUPPORT */

#ifdef WITH_ADDRESS_SANITIZER

#define VERSION_SANITIZER               "+SANITIZER"

#else /* WITH_ADDRESS_SANITIZER */

#define VERSION_SANITIZER               ""

#endif /* WITH_ADDRESS_SANITIZER */

#define VERSION_STRING                  PACKAGE_VERSION VERSION_EXCESSIVE VERSION_VPOPMAIL VERSION_SANITIZER
#define USAGE_MESSAGE_HEADER            "spamdyke-qrv " VERSION_STRING " (C)2015 Sam Clippinger, " PACKAGE_BUGREPORT "\nhttp://www.spamdyke.org/\n\n"

#define MAX_BUF                         1023
#define MAX_ADDRESS                     511
#define MAX_PATH                        4095
#define MAX_COMMAND_BUF                 4095
#define MAX_VALIDATE_DEPTH              10
#define MAX_FILE_BUF                    65535
#define MAX_FILE_LINES                  65536

#define STDIN_FD                        0
#define STDOUT_FD                       1
#define STDERR_FD                       2

#define TIMEOUT_COMMAND_SECS            10
#define TIMEOUT_COMMAND_EXIT_USECS      100000

#define STRLEN(X)                       ((int)(sizeof(X) - 1))
#define _STRINGIFY(X)                   #X
#define STRINGIFY(X)                    _STRINGIFY(X)
#define MINVAL(a,b)                     ({ typeof (a) _a = (a); typeof (b) _b = (b); _a < _b ? _a : _b; })
#define MAXVAL(a,b)                     ({ typeof (a) _a = (a); typeof (b) _b = (b); _a > _b ? _a : _b; })
#define SNPRINTF(BUF,MAX,FORMAT...)     ({ int _tmp = snprintf(BUF, MAX, FORMAT); MINVAL(_tmp, MAX); })

#define ENVIRONMENT_RELAYCLIENT         "RELAYCLIENT"
#define ENVIRONMENT_PATH                "PATH"
#define ENVIRONMENT_DELIMITER           '='
#define ENVIRONMENT_SEPARATOR           ':'
#define COMMENT_DELIMITER               '#'
#define DIR_DELIMETER                   '/'

#define VIRTUALDOMAINS_DELIMITER        ':'

#define PATH_ESCAPE_CHAR                '\\'
#define PATH_QUOTE_CHAR                 '"'

#define DIR_DELIMITER                   '/'
#define DIR_DELIMITER_STR               "/"

#define FILE_PERMISSION_STICKY          0x20
#define FILE_PERMISSION_SETUID          0x10
#define FILE_PERMISSION_SETGID          0x08
#define FILE_PERMISSION_READ            0x04
#define FILE_PERMISSION_WRITE           0x02
#define FILE_PERMISSION_EXECUTE         0x01

#define DEFAULT_PATH                    "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/var/qmail/bin:/home/vpopmail/bin"
#define DEFAULT_QMAIL_PERCENTHACK_FILE  "/var/qmail/control/percenthack"
#define DEFAULT_QMAIL_LOCALS_FILE       "/var/qmail/control/locals"
#define DEFAULT_QMAIL_VIRTUALDOMAINS_FILE       "/var/qmail/control/virtualdomains"
#define DEFAULT_QMAIL_ASSIGN_CDB        "/var/qmail/users/cdb"
#define DEFAULT_QMAIL_DEFAULTDELIVERY_FILE      "/var/qmail/control/defaultdelivery"
#define DEFAULT_QMAIL_ENVNOATHOST_FILE  "/var/qmail/control/envnoathost"
#define DEFAULT_QMAIL_ME_FILE           "/var/qmail/control/me"
#define DEFAULT_QMAIL_RCPTHOSTS_FILE    "/var/qmail/control/rcpthosts"
#define DEFAULT_QMAIL_MORERCPTHOSTS_CDB "/var/qmail/control/morercpthosts.cdb"

#define QMAIL_ASSIGN_PREFIX             '!'
#define QMAIL_ASSIGN_DELIMITER          '\0'
#define QMAIL_REPLACE_EXT_TARGET        '.'
#define QMAIL_REPLACE_EXT_REPLACEMENT   ':'
#define QMAIL_EXT_TRUNCATE_TARGET       '-'
#define QMAIL_DASH_USER_FOUND           "-"
#define QMAIL_USER_TRUNCATE_TARGET      '-'
#define QMAIL_USER_ALIAS                "alias"
#define QMAIL_LINES_PER_READ            10
#define QMAIL_COMMENT                   '#'
#define QMAIL_MBOX_START_CHARS          "./"
#define QMAIL_MBOX_END_NOT_CHAR         '/'
#define QMAIL_MAILDIR_START_CHARS       "./"
#define QMAIL_MAILDIR_END_CHAR          '/'
#define QMAIL_PROGRAM_START_CHAR        '|'
#define QMAIL_FORWARD_START_CHAR        '&'
#define QMAIL_PERCENTHACK_TARGET        '%'

#define DECISION_ERROR                  -1
#define DECISION_UNKNOWN                0
#define DECISION_VALID                  1
#define DECISION_INVALID                2
#define DECISION_UNAVAILABLE            3

#define VPOPMAIL_VDELIVERMAIL           "vdelivermail"
#define VPOPMAIL_BOUNCE                 "bounce-no-mailbox"
#define VPOPMAIL_DELETE                 "delete"
#define VPOPMAIL_VUSERINFO              "vuserinfo"
#define VPOPMAIL_VUSERINFO_ARG          "-d"
#define VPOPMAIL_VALIAS                 "valias"
#define VPOPMAIL_VALIAS_ARG             "-s"
#define VPOPMAIL_VALIAS_DELIMITER       " -> "
#define VPOPMAIL_VDELIVERMAIL_MAILDIR   "Maildir/"

#define QRV_LOG_ERROR(CURRENT_SETTINGS,FORMAT,DATA...)          ({ log_qrv(FORMAT,__func__,__FILE__,__LINE__,DATA); })
#define QRV_LOG_VERBOSE(CURRENT_SETTINGS,FORMAT,DATA...)        ({ if ((CURRENT_SETTINGS != NULL) && ((CURRENT_SETTINGS)->verbose >= 1)) log_qrv(FORMAT,__func__,__FILE__,__LINE__,DATA); })

#ifdef WITH_EXCESSIVE_OUTPUT

#define QRV_LOG_EXCESSIVE(CURRENT_SETTINGS,FORMAT,DATA...)      ({ if ((CURRENT_SETTINGS != NULL) && ((CURRENT_SETTINGS)->verbose >= 2)) log_qrv(FORMAT,__func__,__FILE__,__LINE__,DATA); })
#define QRV_DIAG(CURRENT_SETTINGS,FORMAT,DATA...)               ({ log_qrv(FORMAT,DATA); })

#else /* WITH_EXCESSIVE_OUTPUT */

#define QRV_LOG_EXCESSIVE(CURRENT_SETTINGS,FORMAT,DATA...)      ({ })
#define QRV_DIAG(CURRENT_SETTINGS,FORMAT,DATA...)               ({ })

#endif /* WITH_EXCESSIVE_OUTPUT */

#define LOG_DATA_NULL                   "(NULL)"

#define LOG_ERROR_OPTION_UNKNOWN        "QRV-ERROR(%s()@%s:%d): Unknown command line option: %s"
#define LOG_ERROR_OPTION_MISSING_DOMAIN "QRV-ERROR(%s()@%s:%d): No recipient domain name found!"
#define LOG_ERROR_OPTION_MISSING_USERNAME       "QRV-ERROR(%s()@%s:%d): No recipient username found!"
#define LOG_ERROR_VALIDATE_LOOP         "QRV-ERROR(%s()@%s:%d): recipient validation stuck in an infinite loop!"
#define LOG_ERROR_OPEN_SEARCH           "QRV-ERROR(%s()@%s:%d): unable to open file for searching "
#define LOG_ERROR_MALLOC                "QRV-ERROR(%s()@%s:%d): out of memory - unable to allocate %lu bytes"
#define LOG_ERROR_STAT_ERRNO            "QRV-ERROR(%s()@%s:%d): unable to stat() path %s: %s"
#define LOG_ERROR_OPEN                  "QRV-ERROR(%s()@%s:%d): unable to open file "
#define LOG_ERROR_GETCWD                "QRV-ERROR(%s()@%s:%d): unable to get current working directory: %s"
#define LOG_ERROR_GETUSER_ERRNO         "QRV-ERROR(%s()@%s:%d): unable to find user with name or ID %s: %s"
#define LOG_ERROR_CDB_EOF               "QRV-ERROR(%s()@%s:%d): unable to load data from CDB file %s: unexpected end of file"
#define LOG_ERROR_CDB_READ              "QRV-ERROR(%s()@%s:%d): unable to load data from CDB file %s: "
#define LOG_ERROR_CDB_SEEK              "QRV-ERROR(%s()@%s:%d): unable to find byte offset %ld within CDB file %s: "
#define LOG_ERROR_CDB_OPEN              "QRV-ERROR(%s()@%s:%d): unable to open CDB file %s: "
#define LOG_ERROR_CDB_WILDCARD          "QRV-ERROR(%s()@%s:%d): unable to read wildcard characters from CDB file %s"
#define LOG_ERROR_EXEC                  "QRV-ERROR(%s()@%s:%d): error executing command %s: %s"
#define LOG_ERROR_MOVE_DESCRIPTORS      "QRV-ERROR(%s()@%s:%d): error moving file descriptors: %s"
#define LOG_ERROR_FORK                  "QRV-ERROR(%s()@%s:%d): unable to fork: %s"
#define LOG_ERROR_PIPE                  "QRV-ERROR(%s()@%s:%d): unable to create pipe: %s"
#define LOG_ERROR_COMMAND_ABEND         "QRV-ERROR(%s()@%s:%d): command exited abnormally: %s"
#define LOG_ERROR_INVALID_STATE         "QRV-ERROR(%s()@%s:%d): reached impossible state: current_step = %d, tmp_username = %.*s, tmp_domain = %s, tmp_name = %s, tmp_filename = %s, tmp_path = %s, qmail_dash = %s, qmail_ext = %s"

#define LOG_VERBOSE_FILE_TOO_LONG       "QRV-WARNING(%s@%s:%d): ignoring file content past line %d: "
#define LOG_VERBOSE_RECIPIENT_PERMISSION        "QRV-WARNING(%s@%s:%d): unable to determine recipient validity for address %s: cannot read file %s"
#define LOG_VERBOSE_VALIDATE_DEPTH      "QRV-WARNING(%s@%s:%d): skipping recipient validation for %s: recursive depth is %d, probably due to a forwarding loop"
#define LOG_VERBOSE_INVALID_RECIPIENT   "QRV-DENIED(%s@%s:%d): INVALID RECIPIENT recipient: %s resolved username: %s"
#define LOG_VERBOSE_UNAVAILABLE_RECIPIENT       "QRV-DENIED(%s@%s:%d): UNAVAILABLE RECIPIENT recipient: %s resolved username: %s"
#define LOG_VERBOSE_UNKNOWN             "QRV-UNKNOWN(%s@%s:%d): NO DECISION REACHED"
#define LOG_VERBOSE_VALID               "QRV-ALLOWED(%s@%s:%d): VALID ADDRESS"
#define LOG_VERBOSE_NOT_ROOT            "QRV-WARNING(%s@%s:%d): not running as root, permission problems and false positives are likely; current UID = " FORMAT_UID_T

#define LOG_DIAG_DECISION_PATH          "QRV-DIAG: decision path = %.*s"

#define LOG_EXCESSIVE_OPTIONS_VALIAS    "QRV-EXCESSIVE(%s()@%s:%d): configured option VALIAS_PATH = %s"
#define LOG_EXCESSIVE_OPTIONS_VUSERINFO "QRV-EXCESSIVE(%s()@%s:%d): configured option VUSERINFO_PATH = %s"
#define LOG_EXCESSIVE_OPTIONS_GIVEN     "QRV-EXCESSIVE(%s()@%s:%d): processed command line: %s = %s"
#define LOG_EXCESSIVE_OPTIONS_SET       "QRV-EXCESSIVE(%s()@%s:%d): final option value: %s = %s"
#define LOG_EXCESSIVE_ENVIRONMENT_FOUND "QRV-EXCESSIVE(%s()@%s:%d): found environment variable %.*s: %s"
#define LOG_EXCESSIVE_VALIDATE_STEP     "QRV-EXCESSIVE(%s()@%s:%d): current_step = %d, working_username = %.*s, working_domain = %s, tmp_name = %s, tmp_filename = %s, tmp_path = %s, qmail_dash = %s, qmail_ext = %s"
#define LOG_EXCESSIVE_OPEN_FILE         "QRV-EXCESSIVE(%s()@%s:%d): opened file for reading: %s"
#define LOG_EXCESSIVE_READ_LINE         "QRV-EXCESSIVE(%s()@%s:%d): read %d bytes from %s, line %d: %s"
#define LOG_EXCESSIVE_FILE_STAT         "QRV-EXCESSIVE(%s()@%s:%d): found file with mode %o (want %o), uid %d, gid %d: %s"
#define LOG_EXCESSIVE_FILE_STAT_FAIL    "QRV-EXCESSIVE(%s()@%s:%d): cannot find file %s: %s"
#define LOG_EXCESSIVE_PATH_DEFAULT      "QRV-EXCESSIVE(%s()@%s:%d): no PATH found in environment, using default PATH: %s"
#define LOG_EXCESSIVE_VALIDATE_START    "QRV-EXCESSIVE(%s()@%s:%d): beginning validation for username = %.*s, domain = %s"
#define LOG_EXCESSIVE_VALIDATE_LOOP     "QRV-EXCESSIVE(%s()@%s:%d): stopping validation, forward loop found for username = %.*s, domain = %s"
#define LOG_EXCESSIVE_VALIDATE_PERCENT_FOUND    "QRV-EXCESSIVE(%s()@%s:%d): recipient username contains a percent sign: %s"
#define LOG_EXCESSIVE_VALIDATE_PERCENTHACK_FOUND        "QRV-EXCESSIVE(%s()@%s:%d): found recipient domain in %s, new username: %s new domain: %s"
#define LOG_EXCESSIVE_VALIDATE_LOCALS_FILE      "QRV-EXCESSIVE(%s()@%s:%d): found recipient domain %s in locals file: %s"
#define LOG_EXCESSIVE_VALIDATE_VIRTUALDOMAIN    "QRV-EXCESSIVE(%s()@%s:%d): found recipient domain %s in virtualdomains file %s, line content %s, new username: %s"
#define LOG_EXCESSIVE_VALIDATE_VIRTUALDOMAIN_NONE       "QRV-EXCESSIVE(%s()@%s:%d): did not find recipient domain %s in virtualdomains file %s"
#define LOG_EXCESSIVE_VALIDATE_ASSIGN   "QRV-EXCESSIVE(%s()@%s:%d): found recipient username %s in assign cdb %s: %s"
#define LOG_EXCESSIVE_VALIDATE_ASSIGN_VALUES    "QRV-EXCESSIVE(%s()@%s:%d): loaded assign cdb values: prefix %s home %s dash %s ext %s"
#define LOG_EXCESSIVE_VALIDATE_HOME_NOT_FOUND   "QRV-EXCESSIVE(%s()@%s:%d): home directory not found: %s"
#define LOG_EXCESSIVE_VALIDATE_HOME_NOT_OWNED   "QRV-EXCESSIVE(%s()@%s:%d): home directory %s not owned by %s(%d), owner is %d"
#define LOG_EXCESSIVE_VALIDATE_HOME_WRITEABLE   "QRV-EXCESSIVE(%s()@%s:%d): home directory is world-writable: %s"
#define LOG_EXCESSIVE_VALIDATE_FILE_EXISTS      "QRV-EXCESSIVE(%s()@%s:%d): file exists: %s"
#define LOG_EXCESSIVE_VALIDATE_FILE_DOES_NOT_EXIST      "QRV-EXCESSIVE(%s()@%s:%d): file does not exist: %s"
#define LOG_EXCESSIVE_VALIDATE_FILE_READABLE    "QRV-EXCESSIVE(%s()@%s:%d): file is readable by UID " FORMAT_UID_T ", GID " FORMAT_GID_T " : %s"
#define LOG_EXCESSIVE_VALIDATE_FILE_UNREADABLE  "QRV-EXCESSIVE(%s()@%s:%d): file is not readable by UID " FORMAT_UID_T ", GID " FORMAT_GID_T " : %s"
#define LOG_EXCESSIVE_VALIDATE_FILE_WRITEABLE   "QRV-EXCESSIVE(%s()@%s:%d): file is world-writable: %s"
#define LOG_EXCESSIVE_VALIDATE_USER_NOT_FOUND   "QRV-EXCESSIVE(%s()@%s:%d): user not found: %s"
#define LOG_EXCESSIVE_VALIDATE_NO_DEFAULTDELIVERY       "QRV-EXCESSIVE(%s()@%s:%d): cannot find file and no defaultdelivery file was supplied: %s"
#define LOG_EXCESSIVE_VALIDATE_WILDCARD_SEARCH  "QRV-EXCESSIVE(%s()@%s:%d): wildcard char = %c, position = %d, found char = %c"
#define LOG_EXCESSIVE_VALIDATE_RCPTHOSTS        "QRV-EXCESSIVE(%s()@%s:%d): found recipient domain %s in rcpthosts file %s: line %d"
#define LOG_EXCESSIVE_VALIDATE_MORERCPTHOSTS    "QRV-EXCESSIVE(%s()@%s:%d): found recipient domain %s in morercpthosts.cdb file %s"
#define LOG_EXCESSIVE_CDB_SEARCH        "QRV-EXCESSIVE(%s()@%s:%d): searching CDB file %s for %d byte key = %.*s, hash = %u, main index = %d, num_slots = %d, slot_num = %d"
#define LOG_EXCESSIVE_CDB_HASH          "QRV-EXCESSIVE(%s()@%s:%d): looking for index entry; hash = %u, hash index = %u, main index offset = %lu, num slots = %d, slot number = %lu"
#define LOG_EXCESSIVE_CDB_SLOT          "QRV-EXCESSIVE(%s()@%s:%d): found slot; hash value = %u, data offset = %u"
#define LOG_EXCESSIVE_CDB_RECORD        "QRV-EXCESSIVE(%s()@%s:%d): found record header; key length = %lu, data length = %lu"
#define LOG_EXCESSIVE_CDB_KEY           "QRV-EXCESSIVE(%s()@%s:%d): loaded key, %d bytes: %.*s"
#define LOG_EXCESSIVE_CDB_DATA          "QRV-EXCESSIVE(%s()@%s:%d): loaded data, %d bytes: %s"
#define LOG_EXCESSIVE_CDB_DATA_NULL     "QRV-EXCESSIVE(%s()@%s:%d): found data but did not load: %d bytes"
#define LOG_EXCESSIVE_VPOPMAIL_FOUND    "QRV-EXCESSIVE(%s()@%s:%d): found vpopmail command on line %d"
#define LOG_EXCESSIVE_EXEC              "QRV-EXCESSIVE(%s()@%s:%d): executing command as UID " FORMAT_UID_T ", GID " FORMAT_GID_T ": %s"
#define LOG_EXCESSIVE_COMMAND_EXIT      "QRV-EXCESSIVE(%s()@%s:%d): command exited with code %d: %s"
#define LOG_EXCESSIVE_VPOPMAIL_FILE     "QRV-EXCESSIVE(%s()@%s:%d): found vpopmail command on line %d"
#define LOG_EXCESSIVE_CHILD_OUTPUT      "QRV-EXCESSIVE(%s()@%s:%d): child process output %d bytes: %s"
#define LOG_EXCESSIVE_INVALID_RECIPIENT "QRV-EXCESSIVE(%s()@%s:%d): INVALID RECIPIENT recipient: %s resolved username: %s"
#define LOG_EXCESSIVE_UNAVAILABLE_RECIPIENT     "QRV-EXCESSIVE(%s()@%s:%d): UNAVAILABLE RECIPIENT recipient: %s resolved username: %s"
#define LOG_EXCESSIVE_RELAYCLIENT_NONE  "QRV-EXCESSIVE(%s()@%s:%d): did not find " ENVIRONMENT_RELAYCLIENT " environment variable"
#define LOG_EXCESSIVE_VALIAS_ADDRESS    "QRV-EXCESSIVE(%s()@%s:%d): found address in valias output at position %d: %s"
#define LOG_EXCESSIVE_RECIPIENT_COMPARE "QRV-EXCESSIVE(%s()@%s:%d): comparing new address %s to original recipient address %s%s%s"
#define LOG_EXCESSIVE_SEARCH_FILE       "QRV-EXCESSIVE(%s()@%s:%d): searching file %s for: %.*s"
#define LOG_EXCESSIVE_VERSION           "QRV-EXCESSIVE(%s()@%s:%d): spamdyke-qrv version %s"
#define LOG_EXCESSIVE_CURRENT_LINE      "QRV-EXCESSIVE(%s()@%s:%d): current line: %s"
#define LOG_EXCESSIVE_VPOPMAIL_ASSIGN   "QRV-EXCESSIVE(%s()@%s:%d): qmail prefix (%d bytes): %s, domain (%d bytes): %s"
#define LOG_EXCESSIVE_VPOPMAIL_VIRTUALDOMAINS   "QRV-EXCESSIVE(%s()@%s:%d): domain (%d bytes): %s, virtualdomains line: %s"

struct qrv_settings
  {
  int verbose;
  int diag;
  char **qmail_percenthack_file;
  char **qmail_locals_file;
  char **qmail_virtualdomains_file;
  char **qmail_assign_cdb;
  char **qmail_rcpthosts_file;
  char **qmail_morercpthosts_cdb;
  char *qmail_defaultdelivery_file;
  char *qmail_envnoathost_file;
  char *qmail_me_file;
  char *recipient_domain;
  char *recipient_username;
  char *relayclient;
  char *path;
  char **environment;
  };

#endif /* SPAMDYKE_QRV_H */
