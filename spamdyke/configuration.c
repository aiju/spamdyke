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
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include "spamdyke.h"
#include "usage.h"
#include "dns.h"
#include "log.h"
#include "environment.h"
#include "config_test.h"
#include "search_fs.h"
#include "configuration.h"

extern int opterr;

void init_option_set(struct filter_settings *current_settings, struct option_set *target_options)
  {
  int i;
  union
    {
    int *integer_ptr;
    char **string_ptr;
    char ***string_array_ptr;
    } ptr;

  if (target_options != NULL)
    {
    target_options->container = current_settings;

    target_options->filter_action = FILTER_DECISION_UNDECIDED;
    target_options->prev_filter_action = FILTER_DECISION_UNDECIDED;
    target_options->filter_action_locked = 0;
    target_options->filter_grace = FILTER_GRACE_NONE;

    target_options->rejection = NULL;
    target_options->transient_rejection = NULL;
    target_options->reject_message_buf[0] = '\0';
    target_options->transient_reject_message_buf[0] = '\0';
    target_options->short_reject_message_buf[0] = '\0';
    target_options->transient_short_reject_message_buf[0] = '\0';
    target_options->prev_rejection = NULL;

    target_options->nihdns_primary_server_data[0].sin_addr.s_addr = INADDR_ANY;
    target_options->nihdns_secondary_server_data[0].sin_addr.s_addr = INADDR_ANY;
    target_options->strlen_policy_location = 0;

    for (i = 0; current_settings->option_list[i].value_type != CONFIG_TYPE_NONE; i++)
      switch (current_settings->option_list[i].value_type)
        {
        case CONFIG_TYPE_BOOLEAN:
        case CONFIG_TYPE_INTEGER:
        case CONFIG_TYPE_NAME_ONCE:
        case CONFIG_TYPE_NAME_MULTIPLE:
          if ((current_settings->option_list[i].getter.get_integer != NULL) &&
              ((ptr.integer_ptr = (*(current_settings->option_list[i].getter.get_integer))(target_options)) != NULL))
            *(ptr.integer_ptr) = 0;

          break;
        case CONFIG_TYPE_STRING_SINGLETON:
        case CONFIG_TYPE_FILE_SINGLETON:
        case CONFIG_TYPE_FILE_NOT_DIR_SINGLETON:
        case CONFIG_TYPE_DIR_SINGLETON:
        case CONFIG_TYPE_COMMAND_SINGLETON:
        case CONFIG_TYPE_OPTION_SINGLETON:
          if ((current_settings->option_list[i].getter.get_string != NULL) &&
              ((ptr.string_ptr = (*(current_settings->option_list[i].getter.get_string))(target_options, 0)) != NULL))
            *(ptr.string_ptr) = NULL;

          break;
        case CONFIG_TYPE_STRING_ARRAY:
        case CONFIG_TYPE_FILE_ARRAY:
        case CONFIG_TYPE_FILE_NOT_DIR_ARRAY:
        case CONFIG_TYPE_DIR_ARRAY:
        case CONFIG_TYPE_COMMAND_ARRAY:
        case CONFIG_TYPE_OPTION_ARRAY:
          if ((current_settings->option_list[i].getter.get_string_array != NULL) &&
              ((ptr.string_array_ptr = (*(current_settings->option_list[i].getter.get_string_array))(target_options, 0)) != NULL))
            *(ptr.string_array_ptr) = NULL;

          break;
        }
    }

  return;
  }

void free_string_array(char ***current_string_array, char **base_string_array)
  {
  int i;

  if (current_string_array != NULL)
    {
    if (((*current_string_array) != NULL) &&
        ((*current_string_array) != base_string_array))
      {
      for (i = 0; (*current_string_array)[i] != NULL; i++)
        free((*current_string_array)[i]);

      free(*current_string_array);
      }

    *current_string_array = NULL;
    }

  return;
  }

void reset_current_options(struct filter_settings *current_settings, int *processed_file)
  {
  int i;
  int total;

  if ((current_settings != NULL) &&
      (current_settings->current_options != NULL))
    {
    total = 0;
    if (processed_file != NULL)
      for (i = 0; i < 4; i++)
        total += processed_file[i];

    if (total > 0)
      {
      if ((current_settings->current_options->filter_action != FILTER_DECISION_AUTHENTICATED) &&
          (current_settings->current_options->filter_action != FILTER_DECISION_CONFIG_TEST))
        {
        current_settings->current_options->filter_action = FILTER_DECISION_UNDECIDED;
        current_settings->current_options->prev_filter_action = FILTER_DECISION_UNDECIDED;
        current_settings->current_options->filter_action_locked = 0;
        }

      current_settings->current_options->rejection = NULL;
      current_settings->current_options->transient_rejection = NULL;
      current_settings->current_options->reject_message_buf[0] = '\0';
      current_settings->current_options->transient_reject_message_buf[0] = '\0';
      current_settings->current_options->short_reject_message_buf[0] = '\0';
      current_settings->current_options->transient_short_reject_message_buf[0] = '\0';
      current_settings->current_options->prev_rejection = NULL;
      }
    }

  return;
  }

void free_current_options(struct filter_settings *current_settings, int *processed_file)
  {
  int i;
  int total;
  union
    {
    int *integer_ptr;
    char **string_ptr;
    char ***string_array_ptr;
    } ptr;

  if ((current_settings != NULL) &&
      (current_settings->current_options != NULL) &&
      (current_settings->current_options != &current_settings->base_options))
    {
    total = 0;
    if (processed_file != NULL)
      for (i = 0; i < 4; i++)
        total += processed_file[i];

    /*
     * If a file was loaded from a configuration directory, none of its rejection data
     * should be saved, because that file may have made changes that won't apply to
     * other recipients.  But if not, it's safe to reuse the results so the filters
     * don't have to run multiple times unnecessarily.
     */
    if (total == 0)
      {
      current_settings->base_options.prev_filter_action = current_settings->current_options->prev_filter_action;
      current_settings->base_options.filter_action = current_settings->current_options->filter_action;
      current_settings->base_options.filter_action_locked = current_settings->current_options->filter_action_locked;
      current_settings->base_options.filter_grace = current_settings->current_options->filter_grace;

      if (current_settings->current_options->rejection != NULL)
        {
        if (current_settings->current_options->rejection == &current_settings->current_options->rejection_buf)
          {
          memcpy(&current_settings->base_options.rejection_buf, &current_settings->current_options->rejection_buf, sizeof(struct rejection_data));
          current_settings->base_options.rejection = &current_settings->base_options.rejection_buf;

          memcpy(current_settings->base_options.reject_message_buf, current_settings->current_options->reject_message_buf, sizeof(char) * (MINVAL(strlen(current_settings->current_options->reject_message_buf), MAX_BUF) + 1));
          memcpy(current_settings->base_options.short_reject_message_buf, current_settings->current_options->short_reject_message_buf, sizeof(char) * (MINVAL(strlen(current_settings->current_options->short_reject_message_buf), MAX_BUF) + 1));
          memcpy(current_settings->base_options.reject_reason_buf, current_settings->current_options->reject_reason_buf, sizeof(char) * (MINVAL(strlen(current_settings->current_options->reject_reason_buf), MAX_BUF) + 1));

          if (current_settings->current_options->rejection_buf.reject_message == current_settings->current_options->reject_message_buf)
            current_settings->base_options.rejection_buf.reject_message = current_settings->base_options.reject_message_buf;
          if (current_settings->current_options->rejection_buf.short_reject_message == current_settings->current_options->short_reject_message_buf)
            current_settings->base_options.rejection_buf.short_reject_message = current_settings->base_options.short_reject_message_buf;
          }
        else
          current_settings->base_options.rejection = current_settings->current_options->rejection;
        }

      if (current_settings->current_options->transient_rejection != NULL)
        {
        if (current_settings->current_options->transient_rejection == &current_settings->current_options->transient_rejection_buf)
          {
          memcpy(&current_settings->base_options.transient_rejection_buf, &current_settings->current_options->transient_rejection_buf, sizeof(struct rejection_data));
          current_settings->base_options.transient_rejection = &current_settings->base_options.transient_rejection_buf;

          memcpy(current_settings->base_options.transient_reject_message_buf, current_settings->current_options->transient_reject_message_buf, sizeof(char) * (MINVAL(strlen(current_settings->current_options->transient_reject_message_buf), MAX_BUF) + 1));
          memcpy(current_settings->base_options.transient_short_reject_message_buf, current_settings->current_options->transient_short_reject_message_buf, sizeof(char) * (MINVAL(strlen(current_settings->current_options->transient_short_reject_message_buf), MAX_BUF) + 1));
          memcpy(current_settings->base_options.transient_reject_reason_buf, current_settings->current_options->transient_reject_reason_buf, sizeof(char) * (MINVAL(strlen(current_settings->current_options->transient_reject_reason_buf), MAX_BUF) + 1));

          if (current_settings->current_options->transient_rejection_buf.reject_message == current_settings->current_options->transient_reject_message_buf)
            current_settings->base_options.transient_rejection_buf.reject_message = current_settings->base_options.transient_reject_message_buf;
          if (current_settings->current_options->transient_rejection_buf.short_reject_message == current_settings->current_options->transient_short_reject_message_buf)
            current_settings->base_options.transient_rejection_buf.short_reject_message = current_settings->base_options.transient_short_reject_message_buf;
          }
        else
          current_settings->base_options.transient_rejection = current_settings->current_options->transient_rejection;
        }
      }

    for (i = 0; current_settings->option_list[i].value_type != CONFIG_TYPE_NONE; i++)
      switch (current_settings->option_list[i].value_type)
        {
        case CONFIG_TYPE_BOOLEAN:
        case CONFIG_TYPE_INTEGER:
        case CONFIG_TYPE_NAME_ONCE:
        case CONFIG_TYPE_NAME_MULTIPLE:
          break;
        case CONFIG_TYPE_STRING_SINGLETON:
        case CONFIG_TYPE_FILE_SINGLETON:
        case CONFIG_TYPE_FILE_NOT_DIR_SINGLETON:
        case CONFIG_TYPE_DIR_SINGLETON:
        case CONFIG_TYPE_COMMAND_SINGLETON:
        case CONFIG_TYPE_OPTION_SINGLETON:
          if ((current_settings->option_list[i].getter.get_string != NULL) &&
              ((ptr.string_ptr = (*(current_settings->option_list[i].getter.get_string))(current_settings->current_options, 1)) != NULL) &&
              ((*(ptr.string_ptr)) != NULL) &&
              (*(ptr.string_ptr) != *(*(current_settings->option_list[i].getter.get_string))(&current_settings->base_options, 1)))
            {
            free(*(ptr.string_ptr));
            *(ptr.string_ptr) = NULL;
            }

          break;
        case CONFIG_TYPE_STRING_ARRAY:
        case CONFIG_TYPE_FILE_ARRAY:
        case CONFIG_TYPE_FILE_NOT_DIR_ARRAY:
        case CONFIG_TYPE_DIR_ARRAY:
        case CONFIG_TYPE_COMMAND_ARRAY:
        case CONFIG_TYPE_OPTION_ARRAY:
          if ((current_settings->option_list[i].getter.get_string_array != NULL) &&
              ((ptr.string_array_ptr = (*(current_settings->option_list[i].getter.get_string_array))(current_settings->current_options, 1)) != NULL))
            free_string_array(ptr.string_array_ptr, *(*(current_settings->option_list[i].getter.get_string_array))(&current_settings->base_options, 1));

          break;
        }

    free(current_settings->current_options);
    }

  current_settings->current_options = &current_settings->base_options;

  return;
  }

/*
 * RETURN_VALUE:
 *   no error: current_return_value
 *   error: FILTER_DECISION_ERROR
 */
int copy_base_options(struct filter_settings *current_settings, int current_return_value)
  {
  int return_value;
  struct option_set *tmp_options;

  return_value = current_return_value;

  if (return_value != FILTER_DECISION_ERROR)
    {
    free_current_options(current_settings, NULL);

    if ((tmp_options = (struct option_set *)malloc(sizeof(struct option_set))) != NULL)
      {
      memcpy(tmp_options, &current_settings->base_options, sizeof(struct option_set));

      tmp_options->nihdns_primary_server_data[0].sin_addr.s_addr = INADDR_ANY;
      tmp_options->nihdns_secondary_server_data[0].sin_addr.s_addr = INADDR_ANY;

      current_settings->current_options = tmp_options;
      }
    else
      {
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, sizeof(struct option_set));
      return_value = FILTER_DECISION_ERROR;
      }
    }

  return(return_value);
  }

/*
 * Some explanation here:
 *
 * The goal is to put all of the configuration options and related data in one
 * place, instead of having default values set by one function, command line
 * options set by another function, config file options in yet another function,
 * etc.  That's the purpose of the spamdyke_option structure array.
 *
 * One of the elements of the spamdyke_option structure is a pointer to an
 * accessor function.  However, C doesn't allow anonymous functions and I don't
 * want to write a separate accessor function for every member of the
 * filter_settings structure.  So instead I decided to use a "bracketed
 * expression" like this:
 *   void (*accessor_function)(args) = ({ void tmp_func(args) { body; } &tmp_func; })
 * That works but GCC doesn't allow bracketed expressions at file scope, only
 * inside functions.
 *
 * Unfortunately, GCC also doesn't consider bracketed expressions to be
 * "constant initializers", so they can't be used to initalize a static
 * variable.
 *
 * Still more unfortunately, GCC creates nested functions (within bracketed
 * initializers) on the stack, not within the code segment.  This means pointers
 * to those functions are only valid within the scope of prepare_settings().
 * So, all of spamdyke must be run from within prepare_settings() so the options
 * array will remain valid.
 *
 * It's less obvious than just using a big switch() statement, I know.  But
 * since the "obvious" solution requires multiple switch() statements at
 * multiple places in the code and is very difficult to maintain, I believe this
 * is more elegant overall.  It will also make things much clearer as new
 * configuration options and sources are added (databases, web services,
 * Windows Registry, who knows?).
 */
/*
 * Return value:
 *   exit value for main()
 */
int prepare_settings(int argc, char *argv[], char *envp[], int (*main_function)(struct filter_settings *, int, char **))
  {
  int return_value;
  int continue_processing;
  struct filter_settings tmp_settings;
  struct filter_settings *current_settings;
  int short_code;
  int i;
  int j;
  int tmp_strlen;
  char *tmp_char;
  union
    {
    int *integer_ptr;
    char **string_ptr;
    char ***string_array_ptr;
    } ptr;
  int num_options;
  struct option *tmp_options;
  struct passwd *tmp_passwd;
  struct group *tmp_group;
  char tmp_name[MAX_BUF + 1];
  gid_t tmp_gid;
  uid_t tmp_uid;
  char *group_ptr;
  char tmp_command[MAX_PATH + 1];

  /*
   * NOTE: It is very important that these options be alphabetized by the long
   * option name.  process_config_file() uses a binary search algorithm to match
   * entries.
   *
   * The option_list array is (obviously) very large and confusing.  The purpose
   * is to have only one location in the code where all of the options, their
   * types, their arguments and their descriptions are defined.  This makes
   * adding new options a trivial exercise.
   *
   * Unfortunately, the size and complexity of this array seems to tickle bugs
   * in gcc on FreeBSD systems (and only FreeBSD systems, strangely enough).
   * An extra step in the Makefile to preprocess this file before compilation
   * seems to work around those errors.
   *
   * This array is used in a number of places.  It contains anonymous accessor
   * functions for the variables that hold the option values and it holds the
   * default values of those variables, so the array is used to initialize many
   * variables in the filter_settings structure.  Obviously the array is used
   * when options are being parsed, either from the command line or from
   * configuration files.  Since it contains the name of every option, the
   * acceptable values of every option and a description, it is used when the
   * usage (or "help") message is being printed.  The config-test feature uses
   * the array to check every argument to every option for validity.
   *
   * Each entry in the array is a spamdyke_option structure:
   *   value_type: During option parsing, value_type determines whether the
   *     option should be read as a boolean, an integer or a string.  During
   *     configuration testing, the values are tested to ensure they meet the
   *     defined purpose of the option.  Must be one of the following constants:
   *
   *     CONFIG_TYPE_NONE: This value is only set in the last member of the
   *       option_list array.
   *     CONFIG_TYPE_ALIAS: The option is an alias for another option.  The
   *       long name of the other option should be given in the help_argument
   *       entry.  Alias options only need to set their getopt_option and
   *       help_argument values; all other values are ignored.
   *     CONFIG_TYPE_BOOLEAN: A yes/no option, stored as an integer.
   *     CONFIG_TYPE_INTEGER: An integer value
   *     CONFIG_TYPE_STRING_SINGLETON: A text value, stored only once.  If the
   *       option is encountered multiple times, only the last value will be
   *       retained.  This is not for options that are parsed (e.g. blacklist
   *       entries) but for actual text to be displayed somewhere.
   *     CONFIG_TYPE_STRING_ARRAY: A text value, can be given multiple times.
   *       Each value is retained in an array.  This is not for options that are
   *       parsed (e.g. blacklist entries) but for actual text to be displayed
   *       somewhere.
   *     CONFIG_TYPE_FILE_SINGLETON: A path to a file, not a directory, given as
   *       text, stored only once.  If the option is encountered multiple times,
   *       only the last value will be retained.
   *     CONFIG_TYPE_FILE_NOT_DIR_SINGLETON: A path that must be to a file, not
   *       a directory, given as text, stored only once.  If the option is
   *       encountered multiple times, only the last value will be retained.
   *       This type should only be used for "-file" options that have a
   *       corresponding "-dir" option.
   *     CONFIG_TYPE_FILE_ARRAY: A path to a file, not a directory, given as
   *       text, can be given multiple times.  Each value is retained in an
   *       array.
   *     CONFIG_TYPE_FILE_NOT_DIR_ARRAY: A path that must be to a file, not a
   *       directory, given as text, can be given multiple times.  Each value is
   *       retained in an array.  This type should only be used for "-file"
   *       options that have a corresponding "-dir" option.
   *     CONFIG_TYPE_DIR_SINGLETON: A path that must be to a directory, not a
   *       file, given as text, stored only once.  If the option is encountered
   *       multiple times, only the last value will be retained.
   *     CONFIG_TYPE_DIR_ARRAY: A path that must be to a directory, not a file,
   *       given as text, can be given multiple times.  Each value is retained
   *       in an array.
   *     CONFIG_TYPE_COMMAND_SINGLETON: A command path and arguments, given as
   *       a text string, stored only once.  If the option is encountered
   *       multiple times, only the last value will be retained.
   *     CONFIG_TYPE_COMMAND_ARRAY: A command path and arguments, given as a
   *       text string, can be given multiple times.  Each value is retained in
   *       an array.
   *     CONFIG_TYPE_NAME_ONCE: A text value that is matched against a
   *       predefined array of valid values.  If a match is found, an integer
   *       variable is set to a corresponding value.  Can only be given once.
   *       If the option is encountered multiple times, only the last value will
   *       be retained.  NOTE: The option parsing code uses the value 0 to mean
   *       "unset", so be careful not to list 0 among the valid choices.
   *     CONFIG_TYPE_NAME_MULTIPLE: A text value that is matched against a
   *       predefined array of valid values.  If a match is found, an integer
   *       variable is updated with the bitwise OR of the new value with the old
   *       one.  Can be given multiple times.  NOTE: It is possible to completely
   *       clear a "multiple" value during configuration, leaving the value 0.
   *       The code that uses the value must handle this gracefully.
   *     CONFIG_TYPE_OPTION_SINGLETON: A text value that may be given through a
   *       command line or configuration file option but is more commonly found
   *       listed in a file full of values (e.g. blacklist entries).  Can be
   *       given only once.  If the option is encountered multiple times, only
   *       the last value will be retained.
   *     CONFIG_TYPE_OPTION_ARRAY: A text value that may be given through a
   *       command line or configuration file option but is more commonly found
   *       listed in a file full of values (e.g. blacklist entries).  Can be
   *       given multiple times.  Each value is retained in an array.
   *     CONFIG_TYPE_ACTION_ONCE or CONFIG_TYPE_ACTION_MULTIPLE: An option that
   *       triggers an action as soon as option parsing is complete, as opposed
   *       to setting a variable to be used later.  At this time, both the _ONCE
   *       and _MULTIPLE values mean the same thing.
   *
   *  access_type: During configuration testing, determines the filesystem
   *    permissions that should be expected.  Must be one of the following
   *    constants:
   *
   *    CONFIG_ACCESS_NONE: No filesystem permissions are appropriate, no
   *      testing should be performed.
   *    CONFIG_ACCESS_READ_ONLY: Only read permissions are required.
   *    CONFIG_ACCESS_WRITE_ONLY: Only write permissions are required.
   *    CONFIG_ACCESS_READ_WRITE: Reading and writing permissions are required.
   *    CONFIG_ACCESS_EXECUTE: Execute permissions are required.
   *
   *  location: During option parsing, determines the valid places an option
   *    can be given.  The "help" option is not valid in a configuration file,
   *    for example.  Must be a bitwise OR of one or more of the following
   *    values:
   *
   *    CONFIG_LOCATION_CMDLINE: The option may be given on the command line.
   *    CONFIG_LOCATION_GLOBAL_FILE: The option may be given in a global
   *      configuration file (as opposed to a file within a configuration
   *      directory).
   *    CONFIG_LOCATION_DIR: The option may be given in a file within a
   *      configuration directory.
   *
   * getopt_option: An entry in the array to be passed to getopt_long(),
   *   describing this option.  This structure gives the long and short versions
   *   of the option, along with whether arguments are optional or required.
   *
   * default_value: The default value of the variable that holds the value of
   *   this option.  This value is used when all the variables are initialized.
   *   As a union, only one member needs to be given a value.  The following
   *   union members are available:
   *
   *     integer_value: Used when value_type is CONFIG_TYPE_BOOLEAN,
   *       CONFIG_TYPE_INTEGER, CONFIG_TYPE_NAME_ONCE or
   *       CONFIG_TYPE_NAME_MULTIPLE.
   *     string_value: Used when value_type is anything else.
   *
   * missing_value: If the option accepts an argument but does not require one,
   *   missing_value gives the value stored in the variable if no argument is
   *   given.  As a union, only one member needs to be given a value.  The
   *   following union members are available:
   *
   *     integer_value: Used when value_type is CONFIG_TYPE_BOOLEAN,
   *       CONFIG_TYPE_INTEGER, CONFIG_TYPE_NAME_ONCE or
   *       CONFIG_TYPE_NAME_MULTIPLE.
   *     string_value: Used when value_type is anything else.
   *
   * getter: The function pointer stored in the getter union is used to access
   *   the variable that holds the value of this option.  The functions are
   *   what gcc refers to as "bracketed expressions" and every other language
   *   calls "anonymous functions" -- nameless functions that only exist on the
   *   stack.  As a union, only one member needs to be given a value.  In this
   *   union, each member should be set with a specific macro from spamdyke.h:
   *     get_integer: Set using CONFIG_ACCESSOR_INTEGER(MEMBER) when MEMBER is
   *       an integer variable within the option_set structure.
   *     get_string: Set using CONFIG_ACCESSOR_STRING(MEMBER) when MEMBER is a
   *       string variable (char*) within the option_set structure.
   *     get_string_array: Set using CONFIG_ACCESSOR_STRING_ARRAY(MEMBER) when
   *       MEMBER is an array of strings (char**) within the option_set
   *       structure.
   *
   * validity: The value stored in the validity union is used to determine if
   *   the supplied value(s) are valid.  The following union members are
   *   available:
   *     max_strlen: Used when value_type is *not* CONFIG_TYPE_INTEGER,
   *       CONFIG_TYPE_NAME_ONCE or CONFIG_TYPE_NAME_MULTIPLE.
   *       If the given value is larger than max_strlen, it is truncated at
   *       max_strlen characters.  Setting this field to 0 disables the
   *       truncation.
   *    integer_range: Used when value_type is CONFIG_TYPE_INTEGER.  The
   *       structure members minimum and maximum are the minimum and maximum
   *       acceptable values, respectively.
   *    string_list: Used when value_type is CONFIG_TYPE_NAME_ONCE or
   *      CONFIG_TYPE_NAME_MULTIPLE.  The structure members are:
   *        integers: Must be set to an array of integers.  When an element in
   *          strings is matched, the variable will be set to the integer value
   *          at the same index in the integers array.  The size of the
   *          array must be the size of the strings array, not including the
   *          terminating NULL.  No terminating element is needed in the
   *          integers array.
   *        strings: Must be set to a NULL-terminated array of strings.  When a
   *          value is given, it will be compared to each element in strings to
   *          find a match.
   *
   * set_consequence: Determines what spamdyke should do when this option is
   *   set.  For most options, this should be FILTER_DECISION_UNDECIDED, which
   *   allows spamdyke to continue running normally.  Only two other
   *   FILTER_DECISION values are valid in the option_list array:
   *     FILTER_DECISION_CONFIG_TEST: Run the config-test feature and exit; do
   *       not run spamdyke normally.
   *     FILTER_DECISION_ERROR: An error has occurred; exit immediately.
   *
   * set_grace: Determines how quickly spamdyke will begin sending rejection
   *   messages if this option is set (i.e. how much "grace" incoming
   *   connections are given).  For example, if the empty rDNS filter is
   *   triggered, spamdyke will normally close qmail and begin sending rejection
   *   text immediately.  But if a sender whitelist has been specified,
   *   spamdyke should wait until after the sender has been identified and check
   *   the whitelist before giving up.  spamdyke will use the highest grace
   *   level given by any set option.  The values are (in ascending order):
   *     FILTER_GRACE_NONE: this option has no effect on the grace level
   *     FILTER_GRACE_AFTER_FROM: spamdyke should not close qmail until after
   *       the sender has been identified
   *     FILTER_GRACE_AFTER_TO: spamdyke should not close qmail until after all
   *       recipients have been identified
   *     FILTER_GRACE_AFTER_DATA: spamdyke should not close qmail until the
   *       remote server finishes sending message data
   *
   * test_function: A pointer to a function that can test the value of this
   *   option, if it needs special handling beyond checking the input value is
   *   appropriate.  If checking the type and validity is enough, test_function
   *   should be NULL.  test_function is only used by the config-test feature.
   *
   * additional_set_actions: If setting this option should have additional
   *   side effects, code provided in additional_set_actions will be run after
   *   the value is set.  The value of additional_set_actions should be set
   *   using the CONFIG_SET_ACTION() macro or NULL if no further action is
   *   needed.  NOTE: because options may be given in any order, any side effect
   *   that compares this option's value to another option's value should be
   *   duplicated in the other option's additional_set_actions as well.
   *   Otherwise, reversing the order of the options in the configuration file
   *   or on the command line will change spamdyke's behavior.
   *
   * additional_actions: This field is just like additional_set_actions but it
   *   is evaluated after all options have been parsed and set.  It should be
   *   set using the CONFIG_ACTION() macro.
   *
   * help_argument: Used by usage() when constructing the usage message.  Each
   *   option's long name is printed followed by help_argument, if it is not
   *   NULL.  This gives a way to show required or optional portions of the
   *   argument and give it a name that can be reference in help_text.  If this
   *   option's value_type is CONFIG_TYPE_ALIAS, help_argument should contain
   *   the long version of the real option's name (getopt_option.name).
   *
   * help_text: Used by usage() to describe the option.  This text should always
   *   end by describing the default value of the option.  It is not necessary
   *   to mention whether the option is only accepted once or multiple times;
   *   usage() will do this automatically.  usage() will also perform line
   *   wrapping, so help_text should never include any embedded newlines.
   *
   * value_set: Used internally to track whether the option was set while
   *   initially parsing the command line (needed to tell the difference between
   *   0 values that were never set and 0 values that were deliberately
   *   cleared).  This value does not need to be set in the option_list array.
   */
  struct spamdyke_option option_list[] = {
    {
      CONFIG_TYPE_DIR_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "config-dir", required_argument, NULL, -1 },
      { 0 },
      { 0 },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(configuration_dir) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_AFTER_TO,
      &config_test_configuration_dir,
      NULL,
      NULL,
      "DIR",
      "Read additional configuration options from files in the directory structure at DIR. This option is very complex and tricky to setup. Do not use it unless you really need it."
      " See the documentation for details on how to create the directory structure. Default: do not read configuration from a directory structure."
    },
    {
      CONFIG_TYPE_NAME_MULTIPLE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "config-dir-search", required_argument, NULL, -1 },
      { .integer_value = CONFIG_DIR_SEARCH_FIRST },
      { .integer_value = CONFIG_DIR_SEARCH_FIRST },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(configuration_dir_search) },
      { .string_list =
        {
        .integers = (int []){ CONFIG_DIR_SEARCH_FIRST, CONFIG_DIR_SEARCH_ALL_IP, CONFIG_DIR_SEARCH_ALL_RDNS, CONFIG_DIR_SEARCH_ALL_SENDER, CONFIG_DIR_SEARCH_ALL_RECIPIENT },
        .strings = (char *[]){ "first", "all-ip", "all-rdns", "all-sender", "all-recipient", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "SEARCH",
      "Determines how the configuration directory is searched for matching files: first = find and read the most specific file only, all-ip = find and read all files that match the"
      " IP address of the remote server, all-rdns = find and read all files that match the rDNS name of the remote server, all-sender = find and read all files that match the sender's"
      " email address, all-recipient = find and read all files that match the sender's email address. Requires \"config-dir\". Default: first"
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "config-file", required_argument, NULL, 'f' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(config_file) },
      { 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Read additional configuration options from FILE as though they were given on the command line. Default: do not read configuration from a file."
    },

#ifndef WITHOUT_CONFIG_TEST

    {
      CONFIG_TYPE_ACTION_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "config-test", no_argument, NULL, -1 },
      { 0 },
      { 0 },
      { NULL },
      { 0 },
      FILTER_DECISION_CONFIG_TEST,
      FILTER_GRACE_NONE,
      NULL,
      CONFIG_SET_ACTION(if (current_settings->current_options->log_level == 0) current_settings->current_options->log_level = LOG_LEVEL_ERROR),
      NULL,
      NULL,
      "Tests the configuration as much as possible and reports any errors that can be discovered without actually accepting an incoming message."
      " Use this option with all other options that are given during normal operation. Default: do not test configuration."
    },
    {
      CONFIG_TYPE_OPTION_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "config-test-smtpauth-password", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(test_smtp_auth_password) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "PASSWORD",
      "While testing the configuration with \"config-test\", run the commands given with \"smtp-auth-command\" or \"smtp-auth-command-encryption\" to test authentication processing."
      " Use PASSWORD as the authentication password. This option has no effect unless \"config-test\", \"config-test-smtpauth-username\" and either \"smtp-auth-command\" or"
      " \"smtp-auth-command-encryption\" are given. Default: do not run the commands given with \"smtp-auth-command\" or \"smtp-auth-command-encryption\", only check to see if they"
      " appear to be executable."
    },
    {
      CONFIG_TYPE_OPTION_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "config-test-smtpauth-username", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(test_smtp_auth_username) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "USERNAME",
      "While testing the configuration with \"config-test\", run the commands given with \"smtp-auth-command\" or \"smtp-auth-command-encryption\" to test authentication processing."
      " Use USERNAME as the authentication username. This option has no effect unless \"config-test\", \"config-test-smtpauth-password\" and either \"smtp-auth-command\" or"
      " \"smtp-auth-command-encryption\" are given. Default: do not run the commands given with \"smtp-auth-command\" or \"smtp-auth-command-encryption\", only check to see if they"
      " appear to be executable."
    },

#else /* WITHOUT_CONFIG_TEST */

    {
      CONFIG_TYPE_ACTION_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "config-test", no_argument, NULL, -1 },
      { 0 },
      { 0 },
      { NULL },
      { 0 },
      FILTER_DECISION_CONFIG_TEST,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL
    },
    {
      CONFIG_TYPE_ACTION_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "config-test-smtpauth-password", optional_argument, NULL, -1 },
      { 0 },
      { 0 },
      { NULL },
      { 0 },
      FILTER_DECISION_CONFIG_TEST,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL
    },
    {
      CONFIG_TYPE_ACTION_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "config-test-smtpauth-username", optional_argument, NULL, -1 },
      { 0 },
      { 0 },
      { NULL },
      { 0 },
      FILTER_DECISION_CONFIG_TEST,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL
    },

#endif /* WITHOUT_CONFIG_TEST */

    {
      CONFIG_TYPE_INTEGER,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "connection-timeout-secs", required_argument, NULL, 't' },
      { .integer_value = 0 },
      { .integer_value = 0 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(timeout_connection) },
      { .integer_range = { .minimum = 0, .maximum = INT32_MAX } },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "SECS",
      "Forcibly disconnect after a total of SECS seconds, regardless of activity. A value of 0 disables this feature. Default: 0"
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "dns-blacklist-entry", required_argument, NULL, 'x' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(dnsrbl_fqdn) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "DNSRBL",
      "Check the remote server's IP address against the realtime blackhole list DNSRBL. If it is found, the connection is rejected. Default: do not check any DNS RBLs."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "dns-blacklist-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(dnsrbl_fqdn_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Check the remote server's IP address against each of the realtime blackhole lists found in FILE. If it is found, the connection is rejected. Default: do not check any DNS RBLs."
    },
    {
      CONFIG_TYPE_NAME_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-level", required_argument, NULL, -1 },
      { .integer_value = NIHDNS_LEVEL_AGGRESSIVE },
      { .integer_value = NIHDNS_LEVEL_AGGRESSIVE },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_level) },
      { .string_list =
        {
        .integers = (int []){ NIHDNS_LEVEL_NONE, NIHDNS_LEVEL_NORMAL, NIHDNS_LEVEL_AGGRESSIVE },
        .strings = (char *[]){ "none", "normal", "aggressive", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "LEVEL",
      "Sets the DNS resolver behavior to LEVEL: none = no DNS lookups will be performed, normal = imitate standard system resolver library,"
      " aggressive = aggressively query DNS servers. Default: aggressive"
    },
    {
      CONFIG_TYPE_INTEGER,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-max-retries-primary", required_argument, NULL, -1 },
      { .integer_value = DEFAULT_NIHDNS_ATTEMPTS_PRIMARY },
      { .integer_value = DEFAULT_NIHDNS_ATTEMPTS_PRIMARY },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_attempts_primary) },
      { .integer_range = { .minimum = 0, .maximum = INT32_MAX } },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "NUM",
      "Send at most NUM packets to the primary DNS server(s) before also sending packets to the secondary DNS server(s). Default: " STRINGIFY(DEFAULT_NIHDNS_ATTEMPTS_PRIMARY) "."
    },
    {
      CONFIG_TYPE_INTEGER,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-max-retries-total", required_argument, NULL, -1 },
      { .integer_value = DEFAULT_NIHDNS_ATTEMPTS_TOTAL },
      { .integer_value = DEFAULT_NIHDNS_ATTEMPTS_TOTAL },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_attempts_total) },
      { .integer_range = { .minimum = 1, .maximum = INT32_MAX } },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "NUM",
      "Send at most NUM packets to the DNS server(s) (primary or not) for any DNS query. Default: " STRINGIFY(DEFAULT_NIHDNS_ATTEMPTS_TOTAL) "."
    },
    {
      CONFIG_TYPE_NAME_MULTIPLE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-query-type-a", required_argument, NULL, -1 },
      { .integer_value = CONFIG_DNS_TYPE_A | CONFIG_DNS_TYPE_CNAME },
      { .integer_value = CONFIG_DNS_TYPE_A | CONFIG_DNS_TYPE_CNAME },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_query_type_a) },
      { .string_list =
        {
        .integers = (int []){ CONFIG_DNS_TYPE_A, CONFIG_DNS_TYPE_CNAME },
        .strings = (char *[]){ "a", "cname", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TYPE",
      "Use only TYPE query types when querying DNS for IP addresses. The names of the values correspond to the names of the possible DNS query types."
      " If you have any doubt, DO NOT use this option. Default: a and cname"
    },
    {
      CONFIG_TYPE_NAME_MULTIPLE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-query-type-mx", required_argument, NULL, -1 },
      { .integer_value = CONFIG_DNS_TYPE_MX | CONFIG_DNS_TYPE_A | CONFIG_DNS_TYPE_CNAME },
      { .integer_value = CONFIG_DNS_TYPE_MX | CONFIG_DNS_TYPE_A | CONFIG_DNS_TYPE_CNAME },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_query_type_mx) },
      { .string_list =
        {
        .integers = (int []){ CONFIG_DNS_TYPE_A, CONFIG_DNS_TYPE_CNAME, CONFIG_DNS_TYPE_MX },
        .strings = (char *[]){ "a", "cname", "mx", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TYPE",
      "Use only TYPE query types when querying DNS for MX records. The names of the values correspond to the names of the possible DNS query types."
      " If you have any doubt, DO NOT use this option. Default: a, cname and mx"
    },
    {
      CONFIG_TYPE_NAME_MULTIPLE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-query-type-ptr", required_argument, NULL, -1 },
      { .integer_value = CONFIG_DNS_TYPE_CNAME | CONFIG_DNS_TYPE_PTR },
      { .integer_value = CONFIG_DNS_TYPE_CNAME | CONFIG_DNS_TYPE_PTR },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_query_type_ptr) },
      { .string_list =
        {
        .integers = (int []){ CONFIG_DNS_TYPE_CNAME, CONFIG_DNS_TYPE_PTR },
        .strings = (char *[]){ "cname", "ptr", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TYPE",
      "Use only TYPE query types when querying DNS for reverse DNS records. The names of the values correspond to the names of the possible DNS query types."
      " If you have any doubt, DO NOT use this option. Default: cname and ptr"
    },
    {
      CONFIG_TYPE_NAME_MULTIPLE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-query-type-rbl", required_argument, NULL, -1 },
      { .integer_value = CONFIG_DNS_TYPE_TXT | CONFIG_DNS_TYPE_A | CONFIG_DNS_TYPE_CNAME },
      { .integer_value = CONFIG_DNS_TYPE_TXT | CONFIG_DNS_TYPE_A | CONFIG_DNS_TYPE_CNAME },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_query_type_rbl) },
      { .string_list =
        {
        .integers = (int []){ CONFIG_DNS_TYPE_A, CONFIG_DNS_TYPE_CNAME, CONFIG_DNS_TYPE_TXT },
        .strings = (char *[]){ "a", "cname", "txt", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TYPE",
      "Use only TYPE query types when querying DNS RBLs, DNS RWLs, DNS RHSBLs and DNS RHSWLs. The names of the values correspond to the names of the possible DNS query types."
      " If you have any doubt, DO NOT use this option. Default: a, cname and txt"
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-resolv-conf", required_argument, NULL, -1 },
      { .string_value = DEFAULT_NIHDNS_RESOLVER_FILENAME },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(nihdns_resolv_conf) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Read the list of system nameservers and DNS resolver options from FILE. Default: " DEFAULT_NIHDNS_RESOLVER_FILENAME
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-server-ip", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(nihdns_secondary_server_list) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "IP[:PORT]",
      "After sending a number of packets (set with \"max-dns-packets-primary\") to the primary DNS server(s) (set with \"dns-server-ip-primary\"), begin sending packets to the DNS server at IP"
      " on port PORT (if present, otherwise use port " STRINGIFY(DEFAULT_NIHDNS_PORT) "). Default: nameserver configuration is read from the file given with \"dns-resolv-conf\"."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-server-ip-primary", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(nihdns_primary_server_list) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "IP[:PORT]",
      "Perform initial DNS queries using the DNS server at IP on port PORT (if given, otherwise use port " STRINGIFY(DEFAULT_NIHDNS_PORT) ")."
      " Default: nameserver configuration is read from the file given with \"dns-resolv-conf\"."
    },
    {
      CONFIG_TYPE_NAME_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-spoof", required_argument, NULL, -1 },
      { .integer_value = NIHDNS_SPOOF_ACCEPT_ALL },
      { .integer_value = NIHDNS_SPOOF_ACCEPT_ALL },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_spoof) },
      { .string_list =
        {
        .integers = (int []){ NIHDNS_SPOOF_ACCEPT_ALL, NIHDNS_SPOOF_ACCEPT_SAME_IP, NIHDNS_SPOOF_ACCEPT_SAME_PORT, NIHDNS_SPOOF_REJECT },
        .strings = (char *[]){ "accept-all", "accept-same-ip", "accept-same-port", "reject", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "LEVEL",
      "Sets the tolerance of the DNS resolver to potential spoofing attempts (i.e. when a UDP packet is received from a different IP or port than the query was sent to) to LEVEL:"
      " accept-all = accept all replies regardless of origin, accept-same-ip = accept all replies as long as the IP address is the same (even if the port has changed),"
      " accept-same-port = accept all replies as long as the port is the same (even if the IP has changed), reject = do not accept any reply if the IP address or port has"
      " changed. Default: accept-all"
    },
    {
      CONFIG_TYPE_NAME_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-tcp", required_argument, NULL, -1 },
      { .integer_value = NIHDNS_TCP_NORMAL },
      { .integer_value = NIHDNS_TCP_NORMAL },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_tcp) },
      { .string_list =
        {
        .integers = (int []){ NIHDNS_TCP_NONE, NIHDNS_TCP_NORMAL },
        .strings = (char *[]){ "none", "normal", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "LEVEL",
      "Sets the DNS resolver TCP behavior to LEVEL: none = DNS queries will never be sent via TCP, normal = DNS queries will be sent via TCP if necessary. Default: normal"
    },
    {
      CONFIG_TYPE_INTEGER,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "dns-timeout-secs", required_argument, NULL, -1 },
      { .integer_value = -1 },
      { .integer_value = -1 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(nihdns_timeout_total_secs_parameter) },
      { .integer_range = { .minimum = 0, .maximum = INT32_MAX } },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "SECS",
      "Wait at most SECS seconds for a response to any DNS query. Default: " STRINGIFY(DEFAULT_TIMEOUT_NIHDNS_TOTAL_SECS) "."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "dns-whitelist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(dnsrwl_fqdn) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "DNSWHITELIST",
      "Check the remote server's IP address against the DNS whitelist DNSWHITELIST (essentially a DNSRBL that contains whitelisted IPs). If it is found, all filters are bypassed."
      " Default: do not check any DNS whitelists."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "dns-whitelist-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(dnsrwl_fqdn_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Check the remote server's IP address against each of the DNS whitelists found in FILE (essentially a DNSRBL that contains whitelisted IPs). If it is found, all filters are bypassed."
      " Default: do not check any DNS whitelists."
    },
    {
      CONFIG_TYPE_NAME_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "filter-level", required_argument, NULL, -1 },
      { .integer_value = FILTER_LEVEL_NORMAL },
      { .integer_value = FILTER_LEVEL_NORMAL },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(filter_level) },
      { .string_list =
        {
        .integers = (int []){ FILTER_LEVEL_ALLOW_ALL, FILTER_LEVEL_NORMAL, FILTER_LEVEL_REQUIRE_AUTH, FILTER_LEVEL_REJECT_ALL },
        .strings = (char *[]){ "allow-all", "normal", "require-auth", "reject-all", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "LEVEL",
      "Filter connections at LEVEL: allow-all = allow all connections, regardless of any filter settings; normal = allow or reject connections based on configured filters, require-auth ="
      " reject all unauthenticated connections; reject-all = reject all connections, even if authenticated. Default: normal"
    },
    {
      CONFIG_TYPE_DIR_SINGLETON,
      CONFIG_ACCESS_WRITE_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "full-log-dir", required_argument, NULL, 'L' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(log_dir) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "DIR",
      "Log all SMTP traffic to files in DIR. Handy for troubleshooting delivery problems but not meant to be used long-term. This option imposes a performance penalty!"
      " Default: do not log all traffic."
    },
    {
      CONFIG_TYPE_DIR_ARRAY,
      CONFIG_ACCESS_READ_WRITE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "graylist-dir", required_argument, NULL, 'g' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(graylist_dir) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_noop,
      NULL,
      NULL,
      "DIR",
      "Use DIR for storing graylist files. Graylisting will be performed according to the value \"graylist-level\". Default: no graylisting"
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "graylist-exception-ip-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(graylist_exception_ip) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "IPADDRESS",
      "Use IPADDRESS as an IP address that is an exception from the current graylisting policy. The effect of the exception depends on the value of \"graylist-level\". Default: no exceptions"
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "graylist-exception-ip-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(graylist_exception_ip_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Search FILE for IP addresses that are exceptions from the current graylisting policy. The effect of the exception depends on the value of \"graylist-level\". Default: no exceptions"
    },
    {
      CONFIG_TYPE_DIR_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "graylist-exception-rdns-dir", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(graylist_exception_rdns_dir) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_rdns_dir,
      NULL,
      NULL,
      "DIR",
      "Search DIR for rDNS names that are exceptions from the current graylisting policy. The effect of the exception depends on the value of \"graylist-level\". Default: no exceptions"
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "graylist-exception-rdns-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(graylist_exception_rdns) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "NAME",
      "Use NAME as an rDNS name that is an exception from the current graylisting policy. The effect of the exception depends on the value of \"graylist-level\". Default: no exceptions"
    },
    {
      CONFIG_TYPE_FILE_NOT_DIR_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "graylist-exception-rdns-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(graylist_exception_rdns_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Search FILE for rDNS names that are exceptions from the current graylisting policy. The effect of the exception depends on the value of \"graylist-level\". Default: no exceptions"
    },
    {
      CONFIG_TYPE_NAME_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "graylist-level", required_argument, NULL, -1 },
      { .integer_value = GRAYLIST_LEVEL_NONE },
      { .integer_value = GRAYLIST_LEVEL_NONE },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(graylist_level) },
      { .string_list =
        {
        .integers = (int []){ GRAYLIST_LEVEL_NONE, GRAYLIST_LEVEL_FLAG_ALWAYS | GRAYLIST_LEVEL_FLAG_NO_CREATE, GRAYLIST_LEVEL_FLAG_ALWAYS | GRAYLIST_LEVEL_FLAG_CREATE, GRAYLIST_LEVEL_FLAG_ONLY | GRAYLIST_LEVEL_FLAG_NO_CREATE, GRAYLIST_LEVEL_FLAG_ONLY | GRAYLIST_LEVEL_FLAG_CREATE },
        .strings = (char *[]){ "none", "always", "always-create-dir", "only", "only-create-dir", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_graylist,
      NULL,
      NULL,
      "LEVEL",
      "Sets the graylist filter behavior to LEVEL: none = no graylisting; always = graylist all connections if the domain directories exist, except those that match entries in the exception"
      " files/dirs; always-create-dir = graylist all connections and create the domain directories for local domains if necessary, except those that match entries in the exception files/dirs"
      " (requires values for \"qmail-rcpthosts-file\" or \"qmail-morercpthosts-cdb\"); only = only graylist connections that match entries in an exception file/dir,"
      " if the domain directories exist;"
      " only-create-dir = only graylist connections that match entries in an exception file/dir and create the domain directories for local domains if necessary (requires"
      " values for \"qmail-rcpthosts-file\" or \"qmail-morercpthosts-cdb\"). Any value other than \"none\" requires \"graylist-dir\". Default: none"
    },
    {
      CONFIG_TYPE_INTEGER,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "graylist-max-secs", required_argument, NULL, 'M' },
      { .integer_value = 0 },
      { .integer_value = 0 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(graylist_max_secs) },
      { .integer_range = { .minimum = 0, .maximum = INT32_MAX } },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "SECS",
      "Invalidate graylist entries after they are SECS seconds old. A value of \"0\" prevents entries from ever expiring. Requires \"graylist-dir\" and \"graylist-level\". Default: 0"
    },
    {
      CONFIG_TYPE_INTEGER,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "graylist-min-secs", required_argument, NULL, 'm' },
      { .integer_value = 0 },
      { .integer_value = 0 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(graylist_min_secs) },
      { .integer_range = { .minimum = 0, .maximum = INT32_MAX } },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "SECS",
      "Require a graylist entry to be present for SECS seconds before allowing incoming mail. A value of \"0\" allows mail to be excepted immediately after the initial graylisting."
      " Requires \"graylist-dir\" and \"graylist-level\". Default: 0"
    },
    {
      CONFIG_TYPE_INTEGER,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "greeting-delay-secs", required_argument, NULL, 'e' },
      { .integer_value = 0 },
      { .integer_value = 0 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(check_earlytalker) },
      { .integer_range = { .minimum = 0, .maximum = INT32_MAX } },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "SECS",
      "Delay sending the SMTP greeting banner SECS seconds to see if the remote server begins sending data early. If it does, the connection is rejected. Default: no delay."
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "greylist-dir", required_argument, NULL, -1 },
      .help_argument = "graylist-dir"
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "greylist-exception-ip-entry", required_argument, NULL, -1 },
      .help_argument = "graylist-exception-ip-entry"
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "greylist-exception-ip-file", required_argument, NULL, -1 },
      .help_argument = "graylist-exception-ip-file"
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "greylist-exception-rdns-dir", required_argument, NULL, -1 },
      .help_argument = "graylist-exception-rdns-dir"
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "greylist-exception-rdns-entry", required_argument, NULL, -1 },
      .help_argument = "graylist-exception-rdns-entry"
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "greylist-exception-rdns-file", required_argument, NULL, -1 },
      .help_argument = "graylist-exception-rdns-file"
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "greylist-level", required_argument, NULL, -1 },
      .help_argument = "graylist-level"
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "greylist-max-secs", required_argument, NULL, -1 },
      .help_argument = "graylist-max-secs"
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "greylist-min-secs", required_argument, NULL, -1 },
      .help_argument = "graylist-min-secs"
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "header-blacklist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = ({ char ***access_string_array(struct option_set *current_options, int current_options_only) { return(current_options_only ? NULL : &current_options->container->blacklist_header); } &access_string_array; }) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "VALUE",
      "Reject any message with a header line matching VALUE. Default: do not check headers."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "header-blacklist-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = ({ char ***access_string_array(struct option_set *current_options, int current_options_only) { return(current_options_only ? NULL : &current_options->container->blacklist_header_file); } &access_string_array; }) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Reject any message with a header line matching an entry in FILE.  Default: do not check headers."
    },
    {
      CONFIG_TYPE_ACTION_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "help", no_argument, NULL, 'h' },
      { 0 },
      { 0 },
      { NULL },
      { 0 },
      FILTER_DECISION_ERROR,
      FILTER_GRACE_NONE,
      NULL,
      CONFIG_SET_ACTION(usage(current_settings, USAGE_LEVEL_BRIEF, NULL)),
      NULL,
      NULL,
      "Displays a (shorter) option summary and exits."
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "hostname", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(local_server_name) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "NAME",
      "Use NAME as the fully qualified domain name of this host. This value is only used to create an encrypted challenge during SMTP AUTH challenge-response."
      " NOTE: If the hostname is not provided, the encryption is still quite secure. The hostname only adds a small amount of additional randomness to defeat dictionary-based attacks."
      " Default: " MISSING_LOCAL_SERVER_NAME "."
    },
    {
      CONFIG_TYPE_COMMAND_SINGLETON,
      CONFIG_ACCESS_EXECUTE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "hostname-command", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(local_server_name_command) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "COMMAND",
      "Read the fully qualified domain name of this host from the output of COMMAND. Most often, this value is \"/bin/hostname -f\". This value is only used to create an encrypted"
      " challenge during SMTP AUTH challenge-response. This option is ignored if \"hostname\" or \"hostname-file\" are given."
      " NOTE: If the hostname is not provided, the encryption is still quite secure. The hostname only adds a small amount of additional randomness to defeat dictionary-based attacks."
      " Default: do not read the hostname from a command."
    },
    {
      CONFIG_TYPE_FILE_SINGLETON,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "hostname-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(local_server_name_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Read the fully qualified domain name of this host from the first line of FILE. This value is only used to create an encrypted challenge during SMTP AUTH challenge-response."
      " This option is ignored if \"hostname\" is given."
      " NOTE: If the hostname is not provided, the encryption is still quite secure. The hostname only adds a small amount of additional randomness to defeat dictionary-based attacks."
      " Default: do not read the hostname from a file."
    },
    {
      CONFIG_TYPE_INTEGER,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "idle-timeout-secs", required_argument, NULL, 'T' },
      { .integer_value = 0 },
      { .integer_value = 0 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(timeout_command) },
      { .integer_range = { .minimum = 0, .maximum = INT32_MAX } },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "SECS",
      "Forcibly disconnect after SECS seconds of inactivity. A value of 0 disables this feature. Default: 0"
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "ip-blacklist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_ip) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "IPADDRESS",
      "Reject the connection if the remote server's IP address matches IPADDRESS. Default: do not search."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "ip-blacklist-file", required_argument, NULL, 'B' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_ip_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Reject the connection if the remote server's IP address matches an entry in FILE. Default: do not search."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "ip-in-rdns-keyword-blacklist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_rdns_keyword) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "KEYWORD",
      "Search the remote server's rDNS name for its IP address and KEYWORD. If both are found, the connection is rejected. Default: do not search."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "ip-in-rdns-keyword-blacklist-file", required_argument, NULL, 'k' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_rdns_keyword_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Search the remote server's rDNS name for its IP address and a keyword in FILE. If both are found, the connection is rejected. Default: do not search."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "ip-in-rdns-keyword-whitelist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_rdns_keyword) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "KEYWORD",
      "Search the remote server's rDNS name for its IP address and KEYWORD. If both are found, the connection is whitelisted. Default: do not search."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "ip-in-rdns-keyword-whitelist-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_rdns_keyword_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Search the remote server's rDNS name for its IP address and a keyword in FILE. If both are found, the connection is whitelisted. Default: do not search."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "ip-relay-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(relay_ip) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "IPADDRESS",
      "If the remote server's IP address matches IPADDRESS, allow relaying (sending to non-local recipients) from the remote server. Default: do not allow relaying."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "ip-relay-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(relay_ip_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "If the remote server's IP address matches an entry in FILE, allow relaying (sending to non-local recipients) from the remote server. Default: do not allow relaying."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "ip-whitelist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_ip) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "IPADDRESS",
      "If the remote server's IP address matches IPADDRESS, bypass all filters. Default: do not bypass any filters."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "ip-whitelist-file", required_argument, NULL, 'W' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_ip_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "If the remote server's IP address matches an entry in FILE, bypass all filters. Default: do not search."
    },
    {
      CONFIG_TYPE_NAME_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "log-level", optional_argument, NULL, 'l' },
      { .integer_value = LOG_LEVEL_ERROR },
      { .integer_value = LOG_LEVEL_INFO },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(log_level) },
      { .string_list =
        {
        .integers = (int []){ LOG_LEVEL_NONE, LOG_LEVEL_ERROR, LOG_LEVEL_INFO, LOG_LEVEL_VERBOSE, LOG_LEVEL_DEBUG, LOG_LEVEL_EXCESSIVE },
        .strings = (char *[]){ "none", "error", "info", "verbose", "debug", "excessive", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "LEVEL",
      "Sets the log level to LEVEL: none = no logging; error = errors only; info = error + info; verbose = info + non-critical errors and warnings;"
      " debug = verbose + high-level debug messages; excessive = debug + low-level debug messages."
      " Default when log-level is not given: error; default when log-level is given but LEVEL is not given: info"
    },
    {
      CONFIG_TYPE_NAME_MULTIPLE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "log-target", required_argument, NULL, -1 },
      { .integer_value = LOG_USE_SYSLOG },
      { .integer_value = LOG_USE_STDERR },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(log_target) },
      { .string_list =
        {
        .integers = (int []){ LOG_USE_STDERR, LOG_USE_SYSLOG },
        .strings = (char *[]){ "stderr", "syslog", NULL },
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TARGET",
      "Sends all log messages to TARGET: syslog = system syslogd facility, stderr = standard error (stderr)."
      " Default when TARGET is not given: syslog"
    },
    {
      CONFIG_TYPE_INTEGER,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "max-recipients", required_argument, NULL, 'a' },
      { .integer_value = 0 },
      { .integer_value = 0 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(max_rcpt_to) },
      { .integer_range = { .minimum = 0, .maximum = INT32_MAX } },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "NUM",
      "Allow a maximum of NUM recipients per connection for non-local senders. A value of 0 disables this feature. Default: unlimited recipients per connection."
    },
    {
      CONFIG_TYPE_ACTION_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "more-help", no_argument, NULL, -1 },
      { 0 },
      { 0 },
      { NULL },
      { 0 },
      FILTER_DECISION_ERROR,
      FILTER_GRACE_NONE,
      NULL,
      CONFIG_SET_ACTION(usage(current_settings, USAGE_LEVEL_LONG, NULL)),
      NULL,
      NULL,
      "Displays this help screen and exits."
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "policy-url", required_argument, NULL, 'u' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(policy_location) },
      { .max_strlen = MAX_POLICY },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      CONFIG_SET_ACTION(current_settings->current_options->strlen_policy_location = (current_settings->current_options->policy_location != NULL) ? strlen(current_settings->current_options->policy_location) : 0),
      NULL,
      "URL",
      "Append URL to the rejection message to explain why the rejection occurred. NOTE: most servers hide rejection messages from their users and most users don't read bounce messages."
      " Maximum " STRINGIFY(MAX_POLICY) " characters. Default: no policy URL."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "qmail-morercpthosts-cdb", required_argument, NULL, -1 },
      { .string_value = DEFAULT_QMAIL_MORERCPTHOSTS_CDB },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(qmail_morercpthosts_cdb) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_cdb,
      CONFIG_SET_ACTION(if (current_settings->current_options->relay_level == RELAY_LEVEL_UNSET) current_settings->current_options->relay_level = RELAY_LEVEL_NORMAL;),
      NULL,
      "CDB",
      "Search CDB to determine if mail for a domain is accepted here. NOTE: In order for recipient validation to work correctly, spamdyke needs to use the same input"
      " files as qmail. For that reason, using this option is not recommended. Default: " DEFAULT_QMAIL_MORERCPTHOSTS_CDB " (if it exists)"
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "qmail-rcpthosts-file", required_argument, NULL, 'd' },
      { .string_value = DEFAULT_QMAIL_RCPTHOSTS_FILE },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(qmail_rcpthosts_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_qmail_option,
      CONFIG_SET_ACTION(if (current_settings->current_options->relay_level == RELAY_LEVEL_UNSET) current_settings->current_options->relay_level = RELAY_LEVEL_NORMAL;),
      NULL,
      "FILE",
      "Search FILE to determine if mail for a domain is accepted here. NOTE: In order for recipient validation to work correctly, spamdyke needs to use the same input"
      " files as qmail. For that reason, using this option is not recommended. Default: " DEFAULT_QMAIL_RCPTHOSTS_FILE " (if it exists)"
    },
    {
      CONFIG_TYPE_DIR_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rdns-blacklist-dir", required_argument, NULL, 'b' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_rdns_dir) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_rdns_dir,
      NULL,
      NULL,
      "DIR",
      "Reject the connection if the remote server's rDNS name matches a file in DIR. This option provides much better performance than \"rdns-blacklist-entry\" or \"rdns-blacklist-file\" for"
      " large numbers of entries. Default: do not search."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rdns-blacklist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_rdns) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "NAME",
      "Reject the connection if the remote server's rDNS name matches NAME. Default: do not search."
    },
    {
      CONFIG_TYPE_FILE_NOT_DIR_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rdns-blacklist-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_rdns_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Reject the connection if the remote server's rDNS name matches an entry in FILE. Default: do not search."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "rdns-relay-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(relay_rdns) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "NAME",
      "If the remote server's rDNS name matches NAME, allow relaying (sending to non-local recipients) from the remote server. Default: do not allow relaying."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "rdns-relay-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(relay_rdns_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "If the remote server's rDNS name matches an entry in FILE, allow relaying (sending to non-local recipients) from the remote server. Default: do not allow relaying."
    },
    {
      CONFIG_TYPE_DIR_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rdns-whitelist-dir", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_rdns_dir) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_rdns_dir,
      NULL,
      NULL,
      "DIR",
      "If the remote server's rDNS name matches a file in DIR, bypass all filters. Default: do not search."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rdns-whitelist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_rdns) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "NAME",
      "If the remote server's rDNS name matches NAME, bypass all filters. Default: do not search."
    },
    {
      CONFIG_TYPE_FILE_NOT_DIR_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rdns-whitelist-file", required_argument, NULL, 'w' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_rdns_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "If the remote server's rDNS name matches an entry in FILE, bypass all filters. Default: do not search."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "recipient-blacklist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_recipient) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "ADDRESS",
      "Reject any recipient addresses that match ADDRESS. Default: do not search."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "recipient-blacklist-file", required_argument, NULL, 'S' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_recipient_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Reject any recipient addresses that match entries in FILE. Default: do not search."
    },
    {
      CONFIG_TYPE_COMMAND_ARRAY,
      CONFIG_ACCESS_EXECUTE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "recipient-validation-command", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(recipient_validation_command) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "COMMAND",
      "Execute COMMAND to determine if a recipient address is valid, invalid or unavailable. Most often, COMMAND is the full path to \"spamdyke-qrv\" with any needed flags. This value is"
      " only used if \"reject-recipient\" is \"invalid\", \"unavailable\" or both."
      " Default: do not validate recipient addresses."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "recipient-whitelist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_recipient) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_AFTER_TO,
      NULL,
      NULL,
      NULL,
      "ADDRESS",
      "If the recipient's email address matches ADDRESS, bypass all filters. Default: do not search."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "recipient-whitelist-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_recipient_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_AFTER_TO,
      NULL,
      NULL,
      NULL,
      "FILE",
      "If the recipient's email address matches an entry in FILE, bypass all filters. Default: do not search."
    },
    {
      CONFIG_TYPE_BOOLEAN,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "reject-empty-rdns", optional_argument, NULL, 'r' },
      { .integer_value = 0 },
      { .integer_value = 1 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(check_rdns_exist) },
      { 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      NULL,
      "Reject the connection if the remote server has no rDNS name. Default: do not check for an rDNS name."
    },
    {
      CONFIG_TYPE_BOOLEAN,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "reject-ip-in-cc-rdns", optional_argument, NULL, 'c' },
      { .integer_value = 0 },
      { .integer_value = 1 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(check_ip_in_rdns_cc) },
      { 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      NULL,
      "Search the remote server's rDNS name for its IP address AND a two-letter country code. If both are found, reject the connection. Default: do not search."
    },
    {
      CONFIG_TYPE_NAME_MULTIPLE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "reject-recipient", required_argument, NULL, -1 },
      { .integer_value = REJECT_RECIPIENT_NONE },
      { .integer_value = REJECT_RECIPIENT_NONE },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(reject_recipient) },
      { .string_list =
        {
        .integers = (int []){ REJECT_RECIPIENT_NONE, REJECT_RECIPIENT_SAME_AS_SENDER, REJECT_RECIPIENT_INVALID, REJECT_RECIPIENT_UNAVAILABLE },
        .strings = (char *[]){ "none", "same-as-sender", "invalid", "unavailable", NULL },
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "VALUE",
      "Rejects recipient addresses if any of the given conditions are true: none = deactivates these filters, same-as-sender = reject recipients when the recipient address is identical to the"
      " sender address, invalid = reject nonexistant local recipients (requires \"recipient-validation-command\"), unavailable = reject unavailable recipients: qmail will queue the message"
      " instead of delivering it (requires \"recipient-validation-command\")."
      " Default: none"
    },
    {
      CONFIG_TYPE_NAME_MULTIPLE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "reject-sender", required_argument, NULL, -1 },
      { .integer_value = REJECT_SENDER_NONE },
      { .integer_value = REJECT_SENDER_NONE },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(reject_sender) },
      { .string_list =
        {
        .integers = (int []){ REJECT_SENDER_NONE, REJECT_SENDER_NO_MX, REJECT_SENDER_NOT_LOCAL, REJECT_SENDER_NOT_AUTH, REJECT_SENDER_NOT_AUTH_DOMAIN },
        .strings = (char *[]){ "none", "no-mx", "not-local", "authentication-mismatch", "authentication-domain-mismatch", NULL },
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "VALUE",
      "Rejects sender addresses if any of the given conditions are true: none = deactivates these filters, no-mx = reject senders whose domains have no mail exchangers (no MX or A records),"
      " not-local = reject senders whose domains are not accepted locally (requires values for \"qmail-rcpthosts-file\" or \"qmail-morercpthosts-cdb\"),"
      " authentication-mismatch = reject senders whose email addresses do not entirely match their authentication usernames "
      " (NOTE: this has no effect if the sender does not authenticate; if the authentication username is not an email address it must match the username portion of the sender's email address),"
      " authentication-domain-mismatch = reject senders whose domains do not"
      " match the domain name used in the authentication username (NOTE: this has no effect if the sender does not authenticate or if the authentication username is not an email address)."
      " Default: none"
    },
    {
      CONFIG_TYPE_BOOLEAN,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "reject-unresolvable-rdns", optional_argument, NULL, 'R' },
      { .integer_value = 0 },
      { .integer_value = 1 },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(check_rdns_resolve) },
      { 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      NULL,
      "Reject the connection if the remote server's rDNS name does not resolve (search for an A record). Default: do not attempt to resolve."
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "rejection-text-auth-failure", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_SMTP_AUTH_FAILURE]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when authentication fails for any reason. Default: \"" ERROR_SMTP_AUTH_FAILURE "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "rejection-text-auth-unknown", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_SMTP_AUTH_UNKNOWN]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when SMTP AUTH is rejected because the remote server tries to use an unsupported authentication method. This should never happen."
      " Default: \"" ERROR_SMTP_AUTH_UNKNOWN "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-dns-blacklist", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_RBL]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the remote server's IP address is listed on a DNS blacklist. This text will only be used if the DNS blacklist"
      " does not provide a text message and the name of the DNS blacklist will be appended. Default: \"" ERROR_RBL "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-earlytalker", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_EARLYTALKER]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the remote server sent data before the SMTP greeting banner was sent. Default: \"" ERROR_EARLYTALKER "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-empty-rdns", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_RDNS_MISSING]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the remote server has no rDNS name. Default: \"" ERROR_RDNS_MISSING "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-graylist", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_GRAYLISTED]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked by the graylist filter. Default: \"" ERROR_GRAYLISTED "\""
    },
    {
      .value_type = CONFIG_TYPE_ALIAS,
      .getopt_option = { "rejection-text-greylist", required_argument, NULL, -1 },
      .help_argument = "rejection-text-graylist"
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "rejection-text-header-blacklist", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_HEADER_BLACKLISTED]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a message is blocked because its header contains blacklisted content. Default: \"" ERROR_HEADER_BLACKLISTED "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-ip-blacklist", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_BLACKLIST_IP]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the remote server's IP address is listed in a blacklist file or directory. Default: \"" ERROR_BLACKLIST_IP "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-ip-in-cc-rdns", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_IP_IN_NAME_CC]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the remote server's rDNS name contains its IP address and ends in a country code. Default: \"" ERROR_IP_IN_NAME_CC "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-ip-in-rdns-keyword-blacklist", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_IP_IN_NAME]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the sender's rDNS name contains its IP address and a blacklisted keyword. Default: \"" ERROR_IP_IN_NAME "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-local-recipient", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_RCPT_TO_LOCAL]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked because the recipient address was given with no domain name. Default: \"" ERROR_RCPT_TO_LOCAL "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-max-recipients", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_RCPT_TO]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked because the maximum number of recipients has been reached. Default: \"" ERROR_RCPT_TO "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-rdns-blacklist", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_BLACKLIST_NAME]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the remote server's rDNS name is listed in a blacklist file or directory. Default: \"" ERROR_BLACKLIST_NAME "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-recipient-blacklist", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_RECIPIENT_BLACKLISTED]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked because the recipient's address is listed in a blacklist file. Default: \"" ERROR_RECIPIENT_BLACKLISTED "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-recipient-invalid", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_INVALID_RECIPIENT]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked because the address is invalid and would result in a bounced message from qmail. Default: \"" ERROR_INVALID_RECIPIENT "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-recipient-same-as-sender", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_IDENTICAL_FROM_TO]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked because it is identical to a sender address. Default: \"" ERROR_IDENTICAL_FROM_TO "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-recipient-unavailable", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_UNAVAILABLE_RECIPIENT]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is not accepting mail and qmail will queue the message instead of delivering it. Default: \"" ERROR_UNAVAILABLE_RECIPIENT "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-reject-all", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_UNCONDITIONAL]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because all connections are being rejected. Default: \"" ERROR_UNCONDITIONAL "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-relaying-denied", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_RELAYING_DENIED]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked because the remote server does not have permission to relay. Default: \"" ERROR_RELAYING_DENIED "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-rhs-blacklist", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_RHSBL]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the remote server's rDNS name or the sender's email domain name is listed on a RHS blacklist. This text will"
      " only be used if the RHS blacklist does not provide a text message and the name of the RHS blacklist will be appended. Default: \"" ERROR_RHSBL "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-sender-authentication-mismatch", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_SENDER_NOT_AUTH]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked because the sender's email domain does not match the domain name in the authenticated username. Default: \"" ERROR_SENDER_NOT_AUTH "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-sender-blacklist", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_SENDER_BLACKLISTED]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the sender's address is listed in a blacklist file. Default: \"" ERROR_SENDER_BLACKLISTED "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-sender-no-mx", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_SENDER_NO_MX]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked because the sender's email domain has no mail exchanger. Default: \"" ERROR_SENDER_NO_MX "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-sender-not-local", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_SENDER_NOT_LOCAL]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a recipient is blocked because the sender's email domain is not hosted locally. Default: \"" ERROR_SENDER_NOT_LOCAL "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-smtp-auth-required", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_AUTH_REQUIRED]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the remote server has not authenticated. Default: \"" ERROR_AUTH_REQUIRED "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "rejection-text-timeout", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_TIMEOUT]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection times out. Default: \"" ERROR_TIMEOUT "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "rejection-text-tls-failure", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[FAILURE_TLS]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a SSL/TLS connection cannot be negotiated with the remote client. Default: \"" ERROR_FAILURE_TLS "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rejection-text-unresolvable-rdns", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_RDNS_RESOLVE]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because the remote server's rDNS name does not resolve. Default: \"" ERROR_RDNS_RESOLVE "\""
    },
    {
      CONFIG_TYPE_STRING_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "rejection-text-zero-recipients", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(rejection_text[REJECTION_ZERO_RECIPIENTS]) },
      { .max_strlen = 100 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "TEXT",
      "Use TEXT as the rejection message when a connection is blocked because no valid recipients have been given. Default: \"" ERROR_ZERO_RECIPIENTS "\""
    },
    {
      CONFIG_TYPE_NAME_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "relay-level", required_argument, NULL, -1 },
      { .integer_value = RELAY_LEVEL_UNSET },
      { .integer_value = RELAY_LEVEL_UNSET },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(relay_level) },
      { .string_list =
        {
        .integers = (int []){ RELAY_LEVEL_NO_RELAY, RELAY_LEVEL_NORMAL, RELAY_LEVEL_ALLOW_ALL },
        .strings = (char *[]){ "block-all", "normal", "allow-all", NULL }
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_relay_level,
      NULL,
      NULL,
      "LEVEL",
      "Sets the relaying level to LEVEL: block-all = prevent all relaying (overrides \"ip-relay-entry\", \"ip-relay-file\", \"rdns-relay-entry\" and \"rdns-relay-file\", NOT RECOMMENDED),"
      " requires values for \"qmail-rcpthosts-file\" or \"qmail-morercpthosts-cdb\" to function correctly;"
      " normal = allow relaying when appropriate, requires values for \"qmail-rcpthosts-file\" or \"qmail-morercpthosts-cdb\" to function correctly;"
      " allow-all = allow relaying from all remote hosts, creating an open relay (NOT RECOMMENDED)."
      " Default: normal"
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rhs-blacklist-entry", required_argument, NULL, 'X' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(rhsbl_fqdn) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "RHSBL",
      "Check the remote server's domain name and the sender email address' domain name against the righthand-side blackhole list RHSBL. If it is found, the connection is rejected."
      " Default: do not check any DNS RBLs."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rhs-blacklist-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(rhsbl_fqdn_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Check the remote server's domain name and the sender email address' domain name against each of the righthand-side blackhole lists found in FILE. If it is found, the"
      " connection is rejected. Default: do not check any DNS RBLs."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rhs-whitelist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(rhswl_fqdn) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_AFTER_FROM,
      NULL,
      NULL,
      NULL,
      "RHSWHITELIST",
      "Check the remote server's domain name and the sender email address' domain name against the righthand-side whitelist RHSWHITELIST (essentially an RHSBL that contains whitelisted"
      " domains). If it is found, all filters are bypassed. Default: do not check any RHS whitelists."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "rhs-whitelist-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(rhswl_fqdn_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_AFTER_FROM,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Check the remote server's domain name and the sender email address' domain name against each of the  righthand-side whitelist lists found in FILE (essentially an RHSBL that"
      " contains whitelisted domains). If it is found, all filters are bypassed. Default: do not check any RHS whitelists."
    },
    {
      CONFIG_TYPE_OPTION_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "run-as-user", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(run_user) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "USER[" USER_DELIMITER "GROUP]",
      "Run as the system user with the username or ID USER. If GROUP is provided, also use the system group with the name or ID GROUP. To use this option, the running user must have permission"
      " to switch identities. On most systems, this requires superuser (root) permission. NOTE: All child processes will also be started with this user and group."
      " Default: run the tests as the current user and group."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "sender-blacklist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_sender) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "ADDRESS",
      "Reject the connection if the sender's email address matches ADDRESS. Default: do not search."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "sender-blacklist-file", required_argument, NULL, 's' },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(blacklist_sender_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "FILE",
      "Reject the connection if the sender's email address matches an entry in FILE. Default: do not search."
    },
    {
      CONFIG_TYPE_OPTION_ARRAY,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "sender-whitelist-entry", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_sender) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_AFTER_FROM,
      NULL,
      NULL,
      NULL,
      "ADDRESS",
      "If the sender's email address matches ADDRESS, bypass all filters. Default: do not search."
    },
    {
      CONFIG_TYPE_FILE_ARRAY,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE | CONFIG_LOCATION_DIR,
      { "sender-whitelist-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(whitelist_sender_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_AFTER_FROM,
      NULL,
      NULL,
      NULL,
      "FILE",
      "If the sender's email address matches an entry in FILE, bypass all filters. Default: do not search."
    },
    {
      CONFIG_TYPE_COMMAND_ARRAY,
      CONFIG_ACCESS_EXECUTE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "smtp-auth-command", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string_array = CONFIG_ACCESSOR_STRING_ARRAY(smtp_auth_command) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_noop,
      NULL,
      CONFIG_ACTION(if (((current_settings->current_options->smtp_auth_level & SMTP_AUTH_SET_MASK) == SMTP_AUTH_SET_VALUE_UNSET) && (current_settings->current_options->smtp_auth_command != NULL) && (current_settings->current_options->smtp_auth_command[0] != NULL)) { current_settings->current_options->smtp_auth_level = SMTP_AUTH_LEVEL_VALUE_ON_DEMAND | SMTP_AUTH_SET_VALUE_SET; if (current_settings->current_options->filter_grace < FILTER_GRACE_AFTER_FROM) current_settings->current_options->filter_grace = FILTER_GRACE_AFTER_FROM; }),
      "COMMAND",
      "Perform SMTP AUTH verification using COMMAND. spamdyke will only advertise cleartext authentication methods (unless qmail has been patched to advertise encrypted methods)."
      " If the authentication is valid, all filters will be bypassed. Most often, COMMAND is \"/bin/checkpassword /bin/true\". If \"smtp-auth-level\" is not given, \"smtp-auth-command\""
      " sets \"smtp-auth-level\" to ondemand. Ignored if \"smtp-auth-level\" is set to ondemand or less. Default: do not check authentication."
    },
    {
      CONFIG_TYPE_NAME_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "smtp-auth-level", required_argument, NULL, -1 },
      { .integer_value = SMTP_AUTH_LEVEL_VALUE_OBSERVE | SMTP_AUTH_SET_VALUE_UNSET },
      { .integer_value = SMTP_AUTH_LEVEL_VALUE_OBSERVE | SMTP_AUTH_SET_VALUE_UNSET },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(smtp_auth_level) },
      { .string_list =
        {
        .integers = (int []){ SMTP_AUTH_LEVEL_VALUE_NONE | SMTP_AUTH_SET_VALUE_SET, SMTP_AUTH_LEVEL_VALUE_OBSERVE | SMTP_AUTH_SET_VALUE_SET, SMTP_AUTH_LEVEL_VALUE_ON_DEMAND | SMTP_AUTH_SET_VALUE_SET, SMTP_AUTH_LEVEL_VALUE_ON_DEMAND_ENCRYPTED | SMTP_AUTH_SET_VALUE_SET, SMTP_AUTH_LEVEL_VALUE_ALWAYS | SMTP_AUTH_SET_VALUE_SET, SMTP_AUTH_LEVEL_VALUE_ALWAYS_ENCRYPTED | SMTP_AUTH_SET_VALUE_SET },
        .strings = (char *[]){ "none", "observe", "ondemand", "ondemand-encrypted", "always", "always-encrypted", NULL },
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_smtpauth,
      NULL,
      CONFIG_ACTION(if (((current_settings->current_options->smtp_auth_level & SMTP_AUTH_LEVEL_MASK) != SMTP_AUTH_LEVEL_VALUE_NONE) && (current_settings->current_options->filter_grace < FILTER_GRACE_AFTER_FROM)) current_settings->current_options->filter_grace = FILTER_GRACE_AFTER_FROM),
      "LEVEL",
      "Support SMTP AUTH at LEVEL. LEVEL must be one of: none = do not allow or support SMTP AUTH, even if qmail supports it; observe"
      " = observe and honor authentication with qmail but qmail must offer it; ondemand = observe and honor authentication with qmail or offer and process"
      " authentication if qmail does not offer it; ondemand-encrypted = observe and honor authentication with qmail or offer and process encrypted authentication"
      " if qmail does not offer any; always = always offer and process authentication, even if qmail offers it; always-encrypted"
      " = always offer and process encrypted authentication, even if qmail offers it. Levels ondemand through always-encrypted"
      " require \"smtp-auth-command\". Default: observe"
    },
    {
      CONFIG_TYPE_FILE_SINGLETON,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "tls-certificate-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(tls_certificate_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_tls_certificate,
      NULL,
      NULL,
      "FILE",
      "Offer TLS support using the SSL certificate in FILE. FILE must be in PEM format. If FILE does not also contain the private key, \"tls-privatekey-file\" must be used."
      " Ignored if \"tls-level\" is none."
    },
    {
      CONFIG_TYPE_OPTION_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "tls-cipher-list", required_argument, NULL, -1 },
      { .string_value = DEFAULT_TLS_CIPHER_LIST },
      { .string_value = DEFAULT_TLS_CIPHER_LIST },
      { .get_string = CONFIG_ACCESSOR_STRING(tls_cipher_list) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "STRING",
      "Sets the list of supported TLS ciphers in the OpenSSL library before accepting any TLS connections. For most situations, the default cipher list is acceptable."
      " Ignored if \"tls-level\" is none. Default: " DEFAULT_TLS_CIPHER_LIST
    },
    {
      CONFIG_TYPE_FILE_SINGLETON,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "tls-dhparams-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(tls_dhparams_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_tls_dhparams,
      NULL,
      NULL,
      "FILE",
      "Read DH parameters from FILE for use while creating ephemeral DH keys (used by certain ciphers).  FILE should be in PEM format and can be generated using the \"openssl dhparam\" command."
      " Ignored if \"tls-level\" is none."
    },
    {
      CONFIG_TYPE_NAME_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "tls-level", required_argument, NULL, -1 },
      { .integer_value = TLS_LEVEL_PROTOCOL },
      { .integer_value = TLS_LEVEL_PROTOCOL },
      { .get_integer = CONFIG_ACCESSOR_INTEGER(tls_level) },
      { .string_list =
        {
        .integers = (int []){ TLS_LEVEL_NONE, TLS_LEVEL_PROTOCOL, TLS_LEVEL_PROTOCOL_SPAMDYKE, TLS_LEVEL_SMTPS },
        .strings = (char *[]){ "none", "smtp", "smtp-no-passthrough", "smtps", NULL },
        }
      },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      NULL,
      NULL,
      NULL,
      "LEVEL",
      "Offer TLS support LEVEL. LEVEL must be one of: none = do not support or allow TLS, even if qmail provides it, smtp"
      " = support TLS during SMTP if possible (or allow passthrough if not), smtp-no-passthrough = support TLS during SMTP if possible but do not allow passthrough,"
      " smtps = start TLS as soon as the connection starts (SMTPS). If LEVEL is \"smtp\" and \"tls-certificate-file\""
      " is not given, TLS traffic will be passed through without decryption. If LEVEL is \"smtp-no-passthrough\" or \"smtps\", \"tls-certificate-file\" is required. Default: smtp"
    },
    {
      CONFIG_TYPE_FILE_SINGLETON,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "tls-privatekey-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(tls_privatekey_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_tls_privatekey,
      NULL,
      NULL,
      "FILE",
      "Read the private key for the SSL certificate (from \"tls-certificate-file\") from FILE. FILE must be in PEM format. Requires \"tls-certificate-file\"."
      " Default: find the private key in the certificate file given with \"tls-certificate-file\"."
    },
    {
      CONFIG_TYPE_OPTION_SINGLETON,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "tls-privatekey-password", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(tls_privatekey_password) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_tls_password,
      CONFIG_SET_ACTION(current_settings->current_options->strlen_tls_privatekey_password = (current_settings->current_options->tls_privatekey_password != NULL) ? strlen(current_settings->current_options->tls_privatekey_password) : 0),
      NULL,
      "PASSWORD",
      "Use PASSWORD to decrypt the SSL private key (from \"tls-certificate-file\" or \"tls-privatekey-file\"), if necessary. NOTE: this option reveals the password in the process list!"
      " Requires \"tls-certificate-file\" and/or \"tls-privatekey-file\". Default: assume the private key is not encrypted with a password."
    },
    {
      CONFIG_TYPE_FILE_SINGLETON,
      CONFIG_ACCESS_READ_ONLY,
      CONFIG_LOCATION_CMDLINE | CONFIG_LOCATION_GLOBAL_FILE,
      { "tls-privatekey-password-file", required_argument, NULL, -1 },
      { .string_value = NULL },
      { .string_value = NULL },
      { .get_string = CONFIG_ACCESSOR_STRING(tls_privatekey_password_file) },
      { .max_strlen = 0 },
      FILTER_DECISION_UNDECIDED,
      FILTER_GRACE_NONE,
      &config_test_tls_password,
      NULL,
      NULL,
      "FILE",
      "Read the password to decrypt the private key for the SSL certificate (from \"tls-certificate-file\") from the first line of FILE, if necessary. Requires \"tls-certificate-file\""
      " and/or \"tls-password-file\". Default: assume the private key is not encrypted with a password."
    },
    {
      CONFIG_TYPE_ACTION_ONCE,
      CONFIG_ACCESS_NONE,
      CONFIG_LOCATION_CMDLINE,
      { "version", no_argument, NULL, 'v' },
      { 0 },
      { 0 },
      { NULL },
      { 0 },
      FILTER_DECISION_ERROR,
      FILTER_GRACE_NONE,
      NULL,
      CONFIG_SET_ACTION(usage(current_settings, USAGE_LEVEL_SHORT, NULL)),
      NULL,
      NULL,
      "Displays the version number and copyright statement, then exits."
    },

    { CONFIG_TYPE_NONE }
    };

  /*
   * This is here because the new -Waddress flag in gcc 4.6 will throw warnings
   * when &tmp_settings is used as a parameter to the SPAMDYKE_LOG_* macros. By
   * using a pointer variable, the warning is defeated.
   */
  current_settings = &tmp_settings;

  tmp_settings.option_list = option_list;
  tmp_settings.num_options = (sizeof(option_list) / sizeof(struct spamdyke_option)) - 1;

  init_option_set(&tmp_settings, &tmp_settings.base_options);
  tmp_settings.current_options = &tmp_settings.base_options;

  tmp_settings.current_environment = envp;
  tmp_settings.original_environment = envp;

  /*
   * init_option_set() will initialize all variables referenced in option_list
   * above.  Only the remaining variables need to be initialized here.
   */
  tmp_settings.server_name[0] = '\0';
  tmp_settings.strlen_server_name = 0;
  tmp_settings.server_ip = NULL;
  tmp_settings.tmp_server_ip[0] = '\0';
  tmp_settings.strlen_server_ip = 0;
  tmp_settings.ip_in_server_name = -1;

  tmp_settings.allow_relay = 1;
  tmp_settings.additional_domain_text[0] = '\0';
  tmp_settings.inside_data = 0;
  tmp_settings.inside_header = 0;

  tmp_settings.sender_username[0] = '\0';
  tmp_settings.sender_domain[0] = '\0';
  tmp_settings.recipient_username[0] = '\0';
  tmp_settings.recipient_domain[0] = '\0';
  tmp_settings.allowed_recipients = NULL;
  tmp_settings.num_recipients = 0;

  tmp_settings.configuration_path[0] = '\0';

  tmp_settings.child_argv = NULL;

  tmp_settings.smtp_auth_type = SMTP_AUTH_UNKNOWN;
  tmp_settings.smtp_auth_origin = SMTP_AUTH_ORIGIN_NONE;
  tmp_settings.smtp_auth_state = SMTP_AUTH_STATE_NONE;
  tmp_settings.smtp_auth_challenge[0] = '\0';
  tmp_settings.smtp_auth_response[0] = '\0';
  tmp_settings.smtp_auth_username[0] = '\0';
  tmp_settings.smtp_auth_domain = NULL;

  tmp_settings.current_options->nihdns_timeout_total_secs_system = -1;

  tmp_settings.connection_start = 0;
  tmp_settings.command_start = 0;

  tmp_settings.tls_state = TLS_STATE_INACTIVE;

  tmp_settings.reconstructed_header[0] = '\0';
  tmp_settings.strlen_reconstructed_header = 0;
  tmp_settings.buf_retain = NULL;
  tmp_settings.strlen_buf_retain = 0;
  tmp_settings.max_buf_retain = 0;
  tmp_settings.blacklist_header = NULL;
  tmp_settings.blacklist_header_file = NULL;

#ifdef HAVE_LIBSSL

  tmp_settings.tls_context = NULL;
  tmp_settings.tls_session = NULL;

#endif /* HAVE_LIBSSL */

  continue_processing = 1;

  /*
   * Replace the -1 short codes for getopt_long() with auto-incremented values.
   * The values have to be unique, so this is much better than trying to set
   * them to specific values above.
   */
  tmp_settings.max_short_code = 0;
  num_options = 0;
  for (i = 0; option_list[i].value_type != CONFIG_TYPE_NONE; i++)
    if (option_list[i].getopt_option.val == -1)
      num_options++;
    else if (option_list[i].getopt_option.val > tmp_settings.max_short_code)
      tmp_settings.max_short_code = option_list[i].getopt_option.val;

  if ((tmp_settings.option_lookup = malloc(sizeof(struct spamdyke_option *) * (num_options + tmp_settings.max_short_code + 1))) != NULL)
    {
    for (i = 0; i < (num_options + tmp_settings.max_short_code); i++)
      tmp_settings.option_lookup[i] = NULL;

    short_code = tmp_settings.max_short_code + 1;
    for (i = 0; option_list[i].value_type != CONFIG_TYPE_NONE; i++)
      if (option_list[i].getopt_option.val == -1)
        {
        option_list[i].getopt_option.val = short_code;
        tmp_settings.option_lookup[short_code] = &option_list[i];
        short_code++;
        }
      else
        {
        if (tmp_settings.option_lookup[option_list[i].getopt_option.val] != NULL)
          {
          SPAMDYKE_USAGE(&tmp_settings, USAGE_LEVEL_SHORT, LOG_ERROR_SHORT_OPTION_CONFLICT "\n", option_list[i].getopt_option.val, tmp_settings.option_lookup[option_list[i].getopt_option.val]->getopt_option.name, option_list[i].getopt_option.name);
          continue_processing = 0;
          }

        tmp_settings.option_lookup[option_list[i].getopt_option.val] = &option_list[i];
        }
    }
  else
    {
    SPAMDYKE_USAGE(&tmp_settings, USAGE_LEVEL_SHORT, LOG_ERROR_MALLOC "\n", (unsigned long)(sizeof(struct spamdyke_option *) * (num_options + tmp_settings.max_short_code + 1)));
    continue_processing = 0;
    }

  /* Set some default values */
  for (i = 0; continue_processing && (option_list[i].value_type != CONFIG_TYPE_NONE); i++)
    {
    option_list[i].value_set = 0;

    switch (option_list[i].value_type)
      {
      case CONFIG_TYPE_BOOLEAN:
      case CONFIG_TYPE_INTEGER:
        if ((option_list[i].getter.get_integer != NULL) &&
            ((ptr.integer_ptr = (*(option_list[i].getter.get_integer))(&tmp_settings.base_options)) != NULL))
          *(ptr.integer_ptr) = option_list[i].default_value.integer_value;

        break;
      case CONFIG_TYPE_NAME_ONCE:
      case CONFIG_TYPE_NAME_MULTIPLE:
        if ((option_list[i].getter.get_integer != NULL) &&
            ((ptr.integer_ptr = (*(option_list[i].getter.get_integer))(&tmp_settings.base_options)) != NULL))
          *(ptr.integer_ptr) = 0;

        break;
      case CONFIG_TYPE_STRING_SINGLETON:
      case CONFIG_TYPE_FILE_SINGLETON:
      case CONFIG_TYPE_FILE_NOT_DIR_SINGLETON:
      case CONFIG_TYPE_DIR_SINGLETON:
      case CONFIG_TYPE_COMMAND_SINGLETON:
      case CONFIG_TYPE_OPTION_SINGLETON:
        if ((option_list[i].getter.get_string != NULL) &&
            ((ptr.string_ptr = (*(option_list[i].getter.get_string))(&tmp_settings.base_options, 0)) != NULL))
          {
          *(ptr.string_ptr) = NULL;
          if (option_list[i].default_value.string_value != NULL)
            {
            tmp_strlen = strlen(option_list[i].default_value.string_value);
            if ((tmp_char = (char *)malloc(sizeof(char) * (tmp_strlen + 1))) != NULL)
              {
              memcpy(tmp_char, option_list[i].default_value.string_value, sizeof(char) * tmp_strlen);
              tmp_char[tmp_strlen] = '\0';
              *(ptr.string_ptr) = tmp_char;
              }
            else
              {
              SPAMDYKE_USAGE(&tmp_settings, USAGE_LEVEL_SHORT, LOG_ERROR_MALLOC "\n", (unsigned long)(sizeof(char) * (strlen(option_list[i].default_value.string_value) + 1)));
              continue_processing = 0;
              }
            }
          }

        break;
      case CONFIG_TYPE_STRING_ARRAY:
      case CONFIG_TYPE_FILE_ARRAY:
      case CONFIG_TYPE_FILE_NOT_DIR_ARRAY:
      case CONFIG_TYPE_DIR_ARRAY:
      case CONFIG_TYPE_COMMAND_ARRAY:
      case CONFIG_TYPE_OPTION_ARRAY:
        if ((option_list[i].getter.get_string_array != NULL) &&
            ((ptr.string_array_ptr = (*(option_list[i].getter.get_string_array))(&tmp_settings.base_options, 0)) != NULL))
          *(ptr.string_array_ptr) = NULL;

        break;
      }
    }

  if (continue_processing)
    {
    /* Build the long option array for getopt_long() */
    num_options = 0;
    for (i = 0; option_list[i].value_type != CONFIG_TYPE_NONE; i++)
      if (option_list[i].location & CONFIG_LOCATION_CMDLINE)
        num_options++;

    if ((tmp_options = (struct option *)malloc(sizeof(struct option) * (num_options + 1))) != NULL)
      {
      num_options = 0;
      for (i = 0; option_list[i].value_type != CONFIG_TYPE_NONE; i++)
        if (option_list[i].location & CONFIG_LOCATION_CMDLINE)
          {
          memcpy(&tmp_options[num_options], &option_list[i].getopt_option, sizeof(struct option));
          num_options++;
          }

      memcpy(&tmp_options[num_options], &option_list[i].getopt_option, sizeof(struct option));
      tmp_settings.long_options = tmp_options;
      }

    /* Build the short option array for getopt_long() */
    tmp_settings.short_options[0] = '+';
    tmp_settings.short_options[1] = '\0';
    tmp_strlen = 1;
    for (i = 0; (option_list[i].value_type != CONFIG_TYPE_NONE) && (tmp_strlen < MAX_BUF); i++)
      if ((option_list[i].location & CONFIG_LOCATION_CMDLINE) &&
          (option_list[i].getopt_option.val > 0) &&
          (option_list[i].getopt_option.val <= 255) &&
          isalnum((int)option_list[i].getopt_option.val) &&
          (strchr(tmp_settings.short_options, option_list[i].getopt_option.val) == NULL))
        {
        tmp_settings.short_options[tmp_strlen] = option_list[i].getopt_option.val;
        tmp_strlen++;

        if ((option_list[i].getopt_option.has_arg == required_argument) &&
            (tmp_strlen < MAX_BUF))
          {
          tmp_settings.short_options[tmp_strlen] = ':';
          tmp_strlen++;
          }
        else if ((option_list[i].getopt_option.has_arg == optional_argument) &&
                 ((tmp_strlen + 1) < MAX_BUF))
          {
          tmp_settings.short_options[tmp_strlen] = ':';
          tmp_settings.short_options[tmp_strlen + 1] = ':';
          tmp_strlen += 2;
          }

        tmp_settings.short_options[tmp_strlen] = '\0';
        }
    }

  if (continue_processing)
    tmp_settings.base_options.filter_action = process_command_line(&tmp_settings, argc, argv);

  /* Change user and group IDs */
  if (tmp_settings.current_options->run_user != NULL)
    {
    if ((group_ptr = strstr(tmp_settings.current_options->run_user, USER_DELIMITER)) != NULL)
      {
      group_ptr[0] = '\0';
      group_ptr += STRLEN(USER_DELIMITER);

      if (sscanf(group_ptr, FORMAT_GID_T, &tmp_gid) &&
          snprintf(tmp_name, MAX_BUF, FORMAT_GID_T, tmp_gid) &&
          !strcmp(tmp_name, group_ptr))
        tmp_group = getgrgid(tmp_gid);
      else
        tmp_group = getgrnam(group_ptr);

      if (tmp_group != NULL)
        if (setgid(tmp_group->gr_gid) == 0)
          SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_SETGROUP, tmp_group->gr_name, tmp_group->gr_gid);
        else
          SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SETGROUP, tmp_group->gr_name, tmp_group->gr_gid, strerror(errno));
      else
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_GETGROUP, group_ptr);
      }

    errno = 0;
    if (sscanf(tmp_settings.current_options->run_user, FORMAT_UID_T, &tmp_uid) &&
        snprintf(tmp_name, MAX_BUF, FORMAT_UID_T, tmp_uid) &&
        !strcmp(tmp_name, tmp_settings.current_options->run_user))
      tmp_passwd = getpwuid(tmp_uid);
    else
      tmp_passwd = getpwnam(tmp_settings.current_options->run_user);

    if (tmp_passwd != NULL)
      if (setuid(tmp_passwd->pw_uid) == 0)
        SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_SETUSER, tmp_passwd->pw_name, tmp_passwd->pw_uid);
      else
        SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_SETUSER, tmp_passwd->pw_name, tmp_passwd->pw_uid, strerror(errno));
    else if (errno != 0)
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_GETUSER_ERRNO, tmp_settings.current_options->run_user, strerror(errno));
    else
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_GETUSER, tmp_settings.current_options->run_user);
    }
  else
    SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_NO_SETUSER, ((tmp_passwd = getpwuid(geteuid())) != NULL) ? tmp_passwd->pw_name : LOG_MISSING_DATA, geteuid());

  endpwent();

  if (tmp_settings.current_options->config_file != NULL)
    for (i = 0; tmp_settings.current_options->config_file[i] != NULL; i++)
      if ((tmp_settings.current_options->filter_action = process_config_file(&tmp_settings, tmp_settings.current_options->config_file[i], tmp_settings.current_options->filter_action, CONFIG_LOCATION_GLOBAL_FILE, NULL)) == FILTER_DECISION_ERROR)
        {
        exit(0);
        break;
        }

  /* Set remaining default values */
  for (i = 0; continue_processing && (option_list[i].value_type != CONFIG_TYPE_NONE); i++)
    if (!option_list[i].value_set)
      switch (option_list[i].value_type)
        {
        case CONFIG_TYPE_NAME_ONCE:
        case CONFIG_TYPE_NAME_MULTIPLE:
          if ((option_list[i].getter.get_integer != NULL) &&
              ((ptr.integer_ptr = (*(option_list[i].getter.get_integer))(&tmp_settings.base_options)) != NULL))
            *(ptr.integer_ptr) = option_list[i].default_value.integer_value;

          break;
        case CONFIG_TYPE_STRING_ARRAY:
        case CONFIG_TYPE_OPTION_ARRAY:
          if ((option_list[i].default_value.string_value != NULL) &&
              (option_list[i].getter.get_string_array != NULL) &&
              ((ptr.string_array_ptr = (*(option_list[i].getter.get_string_array))(&tmp_settings.base_options, 0)) != NULL))
            continue_processing = append_string(NULL, ptr.string_array_ptr, option_list[i].default_value.string_value, strlen(option_list[i].default_value.string_value));

          break;
        case CONFIG_TYPE_FILE_ARRAY:
        case CONFIG_TYPE_FILE_NOT_DIR_ARRAY:
        case CONFIG_TYPE_DIR_ARRAY:
          if ((option_list[i].default_value.string_value != NULL) &&
              (option_list[i].getter.get_string_array != NULL) &&
              ((ptr.string_array_ptr = (*(option_list[i].getter.get_string_array))(&tmp_settings.base_options, 0)) != NULL) &&
              (check_path_perms(&tmp_settings, option_list[i].default_value.string_value, 0, 0, NULL, -1, -1) == 1))
            continue_processing = append_string(NULL, ptr.string_array_ptr, option_list[i].default_value.string_value, strlen(option_list[i].default_value.string_value));

          break;
        case CONFIG_TYPE_COMMAND_ARRAY:
          if ((option_list[i].default_value.string_value != NULL) &&
              (option_list[i].getter.get_string_array != NULL) &&
              ((ptr.string_array_ptr = (*(option_list[i].getter.get_string_array))(&tmp_settings.base_options, 0)) != NULL) &&
              (find_command(option_list[i].default_value.string_value, tmp_command, MAX_PATH) > 0) &&
              (check_path_perms(&tmp_settings, tmp_command, 0, 0, NULL, -1, -1) == 1))
            continue_processing = append_string(NULL, ptr.string_array_ptr, option_list[i].default_value.string_value, strlen(option_list[i].default_value.string_value));

          break;
        case CONFIG_TYPE_FILE_SINGLETON:
        case CONFIG_TYPE_FILE_NOT_DIR_SINGLETON:
        case CONFIG_TYPE_DIR_SINGLETON:
          if ((option_list[i].default_value.string_value != NULL) &&
              (option_list[i].getter.get_string != NULL) &&
              ((ptr.string_ptr = (*(option_list[i].getter.get_string))(&tmp_settings.base_options, 0)) != NULL) &&
              !strcmp(*(ptr.string_ptr), option_list[i].default_value.string_value) &&
              (check_path_perms(&tmp_settings, option_list[i].default_value.string_value, 0, 0, NULL, -1, -1) != 1))
            *(ptr.string_ptr) = NULL;

          break;
        case CONFIG_TYPE_COMMAND_SINGLETON:
          if ((option_list[i].default_value.string_value != NULL) &&
              (option_list[i].getter.get_string != NULL) &&
              ((ptr.string_ptr = (*(option_list[i].getter.get_string))(&tmp_settings.base_options, 0)) != NULL) &&
              !strcmp(*(ptr.string_ptr), option_list[i].default_value.string_value) &&
              (find_command(option_list[i].default_value.string_value, tmp_command, MAX_PATH) > 0) &&
              (check_path_perms(&tmp_settings, tmp_command, 0, 0, NULL, -1, -1) != 1))
            *(ptr.string_ptr) = NULL;

          break;
        }

  if ((current_settings->current_options->relay_level == RELAY_LEVEL_UNSET) &&
      ((current_settings->current_options->qmail_rcpthosts_file != NULL) ||
       (current_settings->current_options->qmail_morercpthosts_cdb != NULL)))
    current_settings->current_options->relay_level = RELAY_LEVEL_NORMAL;

  if (continue_processing &&
      (main_function != NULL))
    return_value = (*main_function)(&tmp_settings, argc, argv);
  else
    return_value = 111;

  /* Release all of the allocated memory.  Just for neatness. */
  free_current_options(&tmp_settings, NULL);

  for (i = 0; option_list[i].value_type != CONFIG_TYPE_NONE; i++)
    switch (option_list[i].value_type)
      {
      case CONFIG_TYPE_BOOLEAN:
      case CONFIG_TYPE_INTEGER:
      case CONFIG_TYPE_NAME_ONCE:
      case CONFIG_TYPE_NAME_MULTIPLE:
        break;
      case CONFIG_TYPE_STRING_SINGLETON:
      case CONFIG_TYPE_FILE_SINGLETON:
      case CONFIG_TYPE_FILE_NOT_DIR_SINGLETON:
      case CONFIG_TYPE_DIR_SINGLETON:
      case CONFIG_TYPE_COMMAND_SINGLETON:
      case CONFIG_TYPE_OPTION_SINGLETON:
        if ((option_list[i].getter.get_string != NULL) &&
            ((ptr.string_ptr = (*(option_list[i].getter.get_string))(&tmp_settings.base_options, 0)) != NULL) &&
            ((*(ptr.string_ptr)) != NULL))
          {
          free(*(ptr.string_ptr));
          *(ptr.string_ptr) = NULL;
          }

        break;
      case CONFIG_TYPE_STRING_ARRAY:
      case CONFIG_TYPE_FILE_ARRAY:
      case CONFIG_TYPE_FILE_NOT_DIR_ARRAY:
      case CONFIG_TYPE_DIR_ARRAY:
      case CONFIG_TYPE_COMMAND_ARRAY:
      case CONFIG_TYPE_OPTION_ARRAY:
        if ((option_list[i].getter.get_string_array != NULL) &&
            ((ptr.string_array_ptr = (*(option_list[i].getter.get_string_array))(&tmp_settings.base_options, 0)) != NULL) &&
            ((*(ptr.string_array_ptr)) != NULL))
          {
          for (j = 0; (*(ptr.string_array_ptr))[j] != NULL; j++)
            free((*(ptr.string_array_ptr))[j]);
          free(*(ptr.string_array_ptr));
          *(ptr.string_array_ptr) = NULL;
          }

        break;
      }

  if (tmp_settings.option_lookup != NULL)
    {
    free(tmp_settings.option_lookup);
    tmp_settings.option_lookup = NULL;
    }

  if (tmp_settings.long_options != NULL)
    {
    free(tmp_settings.long_options);
    tmp_settings.long_options = NULL;
    }

  if (tmp_settings.buf_retain != NULL)
    {
    free(tmp_settings.buf_retain);
    tmp_settings.buf_retain = NULL;
    }

  free_string_array(&tmp_settings.allowed_recipients, NULL);
  free_string_array(&tmp_settings.blacklist_header, NULL);
  free_string_array(&tmp_settings.blacklist_header_file, NULL);

  free_environment(tmp_settings.original_environment, &tmp_settings.current_environment, NULL);

  return(return_value);
  }

void print_configuration(struct filter_settings *current_settings)
  {
  int i;
  int j;
  union
    {
    int *integer_ptr;
    char **string_ptr;
    char ***string_array_ptr;
    } ptr;
  char tmp_data[MAX_BUF + 1];
  int strlen_data;

  if (current_settings->current_options->log_dir != NULL)
    {
    for (i = 0; current_settings->option_list[i].value_type != CONFIG_TYPE_NONE; i++)
      if (current_settings->option_list[i].help_text != NULL)
        switch (current_settings->option_list[i].value_type)
          {
          case CONFIG_TYPE_BOOLEAN:
          case CONFIG_TYPE_INTEGER:
            if ((current_settings->option_list[i].getter.get_integer != NULL) &&
                ((ptr.integer_ptr = (*current_settings->option_list[i].getter.get_integer)(current_settings->current_options)) != NULL) &&
                ((*(ptr.integer_ptr)) != current_settings->option_list[i].default_value.integer_value))
              {
              strlen_data = SNPRINTF(tmp_data, MAX_BUF, "%s" VALUE_DELIMITER "%d\n", current_settings->option_list[i].getopt_option.name, *(ptr.integer_ptr));
              output_writeln(current_settings, LOG_ACTION_CURRENT_CONFIG, -1, tmp_data, strlen_data);
              }

            break;
          case CONFIG_TYPE_NAME_ONCE:
            if ((current_settings->option_list[i].getter.get_integer != NULL) &&
                ((ptr.integer_ptr = (*current_settings->option_list[i].getter.get_integer)(current_settings->current_options)) != NULL) &&
                ((*(ptr.integer_ptr)) != current_settings->option_list[i].default_value.integer_value))
              for (j = 0; current_settings->option_list[i].validity.string_list.strings[j] != NULL; j++)
                if ((*(ptr.integer_ptr)) == current_settings->option_list[i].validity.string_list.integers[j])
                  {
                  strlen_data = SNPRINTF(tmp_data, MAX_BUF, "%s" VALUE_DELIMITER "%s\n", current_settings->option_list[i].getopt_option.name, current_settings->option_list[i].validity.string_list.strings[j]);
                  output_writeln(current_settings, LOG_ACTION_CURRENT_CONFIG, -1, tmp_data, strlen_data);

                  break;
                  }

            break;
          case CONFIG_TYPE_NAME_MULTIPLE:
            if ((current_settings->option_list[i].getter.get_integer != NULL) &&
                ((ptr.integer_ptr = (*current_settings->option_list[i].getter.get_integer)(current_settings->current_options)) != NULL) &&
                ((*(ptr.integer_ptr)) != current_settings->option_list[i].default_value.integer_value))
              for (j = 0; current_settings->option_list[i].validity.string_list.strings[j] != NULL; j++)
                if (((*(ptr.integer_ptr)) & current_settings->option_list[i].validity.string_list.integers[j]) != 0)
                  {
                  strlen_data = SNPRINTF(tmp_data, MAX_BUF, "%s" VALUE_DELIMITER "%s\n", current_settings->option_list[i].getopt_option.name, current_settings->option_list[i].validity.string_list.strings[j]);
                  output_writeln(current_settings, LOG_ACTION_CURRENT_CONFIG, -1, tmp_data, strlen_data);
                  }

            break;
          case CONFIG_TYPE_STRING_SINGLETON:
          case CONFIG_TYPE_FILE_SINGLETON:
          case CONFIG_TYPE_FILE_NOT_DIR_SINGLETON:
          case CONFIG_TYPE_DIR_SINGLETON:
          case CONFIG_TYPE_COMMAND_SINGLETON:
          case CONFIG_TYPE_OPTION_SINGLETON:
            if ((current_settings->option_list[i].getter.get_string != NULL) &&
                ((ptr.string_ptr = (*current_settings->option_list[i].getter.get_string)(current_settings->current_options, 0)) != NULL) &&
                ((*(ptr.string_ptr)) != NULL) &&
                ((current_settings->option_list[i].default_value.string_value == NULL) ||
                 (strcmp((*(ptr.string_ptr)), current_settings->option_list[i].default_value.string_value) != 0)))
              {
              strlen_data = SNPRINTF(tmp_data, MAX_BUF, "%s" VALUE_DELIMITER "%s\n", current_settings->option_list[i].getopt_option.name, *(ptr.string_ptr));
              output_writeln(current_settings, LOG_ACTION_CURRENT_CONFIG, -1, tmp_data, strlen_data);
              }

            break;
          case CONFIG_TYPE_STRING_ARRAY:
          case CONFIG_TYPE_FILE_ARRAY:
          case CONFIG_TYPE_FILE_NOT_DIR_ARRAY:
          case CONFIG_TYPE_DIR_ARRAY:
          case CONFIG_TYPE_COMMAND_ARRAY:
          case CONFIG_TYPE_OPTION_ARRAY:
            if ((current_settings->option_list[i].getter.get_string_array != NULL) &&
                ((ptr.string_array_ptr = (*current_settings->option_list[i].getter.get_string_array)(current_settings->current_options, 0)) != NULL) &&
                ((*(ptr.string_array_ptr)) != NULL))
              for (j = 0; (*(ptr.string_array_ptr))[j] != NULL; j++)
                if ((current_settings->option_list[i].default_value.string_value == NULL) ||
                    (strcmp((*(ptr.string_array_ptr))[j], current_settings->option_list[i].default_value.string_value) != 0))
                  {
                  strlen_data = SNPRINTF(tmp_data, MAX_BUF, "%s" VALUE_DELIMITER "%s\n", current_settings->option_list[i].getopt_option.name, (*(ptr.string_array_ptr))[j]);
                  output_writeln(current_settings, LOG_ACTION_CURRENT_CONFIG, -1, tmp_data, strlen_data);
                  }

            break;
          }

    output_writeln(current_settings, LOG_ACTION_NONE, -1, NULL, 0);
    }

  return;
  }

/*
 * Expects:
 *   *target_list must be NULL or a heap-allocated NULL terminated array of strings
 *
 * Return value:
 *   ERROR: 0
 *   SUCCESS: 1
 */
int append_string(struct filter_settings *current_settings, char ***target_list, char *target_string, int strlen_target_string)
  {
  int return_value;
  int i;
  char *tmp_char;
  char **tmp_array;

  return_value = 0;

  if ((*target_list) != NULL)
    for (i = 0; (*target_list)[i] != NULL; i++);
  else
    i = 0;

  tmp_char = NULL;
  if ((strlen_target_string == -1) ||
      ((tmp_char = malloc(sizeof(char) * (strlen_target_string + 1))) != NULL))
    if ((tmp_array = realloc((*target_list), sizeof(char *) * (i + 2))) != NULL)
      {
      if (strlen_target_string >= 0)
        {
        memcpy(tmp_char, target_string, sizeof(char) * strlen_target_string);
        tmp_char[strlen_target_string] = '\0';
        tmp_array[i] = tmp_char;
        }
      else
        tmp_array[i] = target_string;

      tmp_array[i + 1] = NULL;
      *target_list = tmp_array;

      return_value = 1;
      }
    else
      {
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char *) * (i + 2)));
      free(tmp_char);
      }
  else
    SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char) * (strlen_target_string + 1)));

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: FILTER_DECISION_ERROR
 *   SUCCESS: if a value was set, FILTER_DECISION from target_option.  If no value was set, current_return_value
 */
int set_config_value(struct filter_settings *current_settings, int context, struct spamdyke_option *target_option, char *input_value, int current_return_value, struct previous_action *history)
  {
  int return_value;
  int i;
  int j;
  int tmp_int;
  int64_t tmp_long_long;
  int changed_value;
  int found_match;
  char *tmp_char;
  union
    {
    int *integer_ptr;
    char **string_ptr;
    char ***string_array_ptr;
    } ptr;
  char usage_text[MAX_BUF + 1];
  int strlen_usage_text;
  char **tmp_base_string_array;
  int remove_value;
  char *input_value_ptr;

  return_value = current_return_value;
  changed_value = 0;
  remove_value = 0;

  if (target_option != NULL)
    switch (target_option->value_type)
      {
      case CONFIG_TYPE_ACTION_ONCE:
      case CONFIG_TYPE_ACTION_MULTIPLE:
        changed_value = 1;

        if (current_settings->current_options->filter_grace < target_option->set_grace)
          current_settings->current_options->filter_grace = target_option->set_grace;

        if (return_value < target_option->set_consequence)
          return_value = target_option->set_consequence;

        break;
      case CONFIG_TYPE_BOOLEAN:
        if ((target_option->getter.get_integer != NULL) &&
            ((ptr.integer_ptr = (*(target_option->getter.get_integer))(current_settings->current_options)) != NULL))
          if (input_value != NULL)
            {
            if (strchr(COMMAND_LINE_TRUE, input_value[0]) != NULL)
              {
              if ((*(ptr.integer_ptr)) != 1)
                {
                *(ptr.integer_ptr) = 1;
                changed_value = 1;

                if (current_settings->current_options->filter_grace < target_option->set_grace)
                  current_settings->current_options->filter_grace = target_option->set_grace;

                if (return_value < target_option->set_consequence)
                  return_value = target_option->set_consequence;
                }
              }
            else if (strchr(COMMAND_LINE_FALSE, input_value[0]) != NULL)
              {
              if ((*(ptr.integer_ptr)) != 0)
                {
                *(ptr.integer_ptr) = 0;
                changed_value = 1;

                if (current_settings->current_options->filter_grace < target_option->set_grace)
                  current_settings->current_options->filter_grace = target_option->set_grace;

                if (return_value < target_option->set_consequence)
                  return_value = target_option->set_consequence;
                }
              }
            else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
              {
              SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_BAD_VALUE "\n", target_option->getopt_option.name, input_value);
              return_value = FILTER_DECISION_ERROR;
              }
            else
              SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_VALUE, target_option->getopt_option.name, input_value);
            }
          else if ((*(ptr.integer_ptr)) != target_option->missing_value.integer_value)
            {
            *(ptr.integer_ptr) = target_option->missing_value.integer_value;
            changed_value = 1;

            if (current_settings->current_options->filter_grace < target_option->set_grace)
              current_settings->current_options->filter_grace = target_option->set_grace;

            if (return_value < target_option->set_consequence)
              return_value = target_option->set_consequence;
            }
          else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
            {
            SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_BAD_VALUE "\n", target_option->getopt_option.name, input_value);
            return_value = FILTER_DECISION_ERROR;
            }
          else
            SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_VALUE, target_option->getopt_option.name, input_value);
        else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
          {
          SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_UNKNOWN_OPTION "\n", target_option->getopt_option.name);
          return_value = FILTER_DECISION_ERROR;
          }
        else
          SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_UNKNOWN_OPTION, target_option->getopt_option.name);

        break;
      case CONFIG_TYPE_INTEGER:
        if ((target_option->getter.get_integer != NULL) &&
            ((ptr.integer_ptr = (*(target_option->getter.get_integer))(current_settings->current_options)) != NULL))
          if (input_value != NULL)
            if (sscanf(input_value, FORMAT_INT64_T, &tmp_long_long) == 1)
              if ((tmp_long_long >= target_option->validity.integer_range.minimum) &&
                  (tmp_long_long <= target_option->validity.integer_range.maximum))
                {
                if ((*(ptr.integer_ptr)) != (int)tmp_long_long)
                  {
                  *(ptr.integer_ptr) = (int)tmp_long_long;
                  changed_value = 1;

                  if (current_settings->current_options->filter_grace < target_option->set_grace)
                    current_settings->current_options->filter_grace = target_option->set_grace;

                  if (return_value < target_option->set_consequence)
                    return_value = target_option->set_consequence;
                  }
                }
              else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
                {
                SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_BAD_INTEGER_RANGE "\n", target_option->getopt_option.name, input_value, target_option->validity.integer_range.minimum, target_option->validity.integer_range.maximum);
                return_value = FILTER_DECISION_ERROR;
                }
              else
                SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_INTEGER_RANGE, target_option->getopt_option.name, input_value, target_option->validity.integer_range.minimum, target_option->validity.integer_range.maximum);
            else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
              {
              SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_BAD_VALUE "\n", target_option->getopt_option.name, input_value);
              return_value = FILTER_DECISION_ERROR;
              }
            else
              SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_VALUE, target_option->getopt_option.name, input_value);
          else if ((*(ptr.integer_ptr)) != target_option->missing_value.integer_value)
            {
            *(ptr.integer_ptr) = target_option->missing_value.integer_value;
            changed_value = 1;

            if (current_settings->current_options->filter_grace < target_option->set_grace)
              current_settings->current_options->filter_grace = target_option->set_grace;

            if (return_value < target_option->set_consequence)
              return_value = target_option->set_consequence;
            }
          else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
            {
            SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_BAD_VALUE "\n", target_option->getopt_option.name, input_value);
            return_value = FILTER_DECISION_ERROR;
            }
          else
            SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_VALUE, target_option->getopt_option.name, input_value);
        else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
          {
          SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_UNKNOWN_OPTION "\n", target_option->getopt_option.name);
          return_value = FILTER_DECISION_ERROR;
          }
        else
          SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_UNKNOWN_OPTION, target_option->getopt_option.name);

        break;
      case CONFIG_TYPE_NAME_ONCE:
      case CONFIG_TYPE_NAME_MULTIPLE:
        if ((target_option->getter.get_integer != NULL) &&
            ((ptr.integer_ptr = (*(target_option->getter.get_integer))(current_settings->current_options)) != NULL))
          if (input_value != NULL)
            {
            if (strcmp(input_value, CONFIG_VALUE_CANCEL) == 0)
              {
              *(ptr.integer_ptr) = 0;
              input_value_ptr = NULL;
              changed_value = 1;
              }
            else if (strncmp(input_value, CONFIG_VALUE_REMOVE, STRLEN(CONFIG_VALUE_REMOVE)) == 0)
              {
              input_value_ptr = input_value + STRLEN(CONFIG_VALUE_REMOVE);
              remove_value = 1;
              }
            else
              {
              input_value_ptr = input_value;
              remove_value = 0;
              }

            if (input_value_ptr != NULL)
              {
              for (j = 0; target_option->validity.string_list.strings[j] != NULL; j++)
                if (strcasecmp(input_value_ptr, target_option->validity.string_list.strings[j]) == 0)
                  {
                  if (((target_option->value_type == CONFIG_TYPE_NAME_ONCE) &&
                       ((*(ptr.integer_ptr)) != target_option->validity.string_list.integers[j])) ||
                      ((target_option->value_type == CONFIG_TYPE_NAME_MULTIPLE) &&
                       ((!remove_value &&
                         (((*(ptr.integer_ptr)) & target_option->validity.string_list.integers[j]) == 0)) ||
                        (remove_value &&
                         (((*(ptr.integer_ptr)) & target_option->validity.string_list.integers[j]) == target_option->validity.string_list.integers[j])))))
                    {
                    if (!remove_value)
                      if ((target_option->value_type == CONFIG_TYPE_NAME_ONCE) ||
                          (target_option->validity.string_list.integers[j] == 0))
                        *(ptr.integer_ptr) = target_option->validity.string_list.integers[j];
                      else
                        *(ptr.integer_ptr) |= target_option->validity.string_list.integers[j];
                    else
                      *(ptr.integer_ptr) &= ~target_option->validity.string_list.integers[j];

                    changed_value = 1;

                    if (current_settings->current_options->filter_grace < target_option->set_grace)
                      current_settings->current_options->filter_grace = target_option->set_grace;

                    if (return_value < target_option->set_consequence)
                      return_value = target_option->set_consequence;
                    }

                  break;
                  }

              if (target_option->validity.string_list.strings[j] == NULL)
                {
                usage_text[0] = '\0';
                if (target_option->validity.string_list.strings[0] != NULL)
                  {
                  strlen_usage_text = SNPRINTF(usage_text, MAX_BUF, "%s", target_option->validity.string_list.strings[0]);
                  for (j = 1; target_option->validity.string_list.strings[j] != NULL; j++)
                    {
                    snprintf(usage_text + strlen_usage_text, MAX_BUF - strlen_usage_text, ", %s", target_option->validity.string_list.strings[j]);
                    strlen_usage_text += strlen(usage_text + strlen_usage_text);
                    }
                  }

                if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
                  {
                  SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_BAD_NAME "\n", target_option->getopt_option.name, input_value, usage_text);
                  return_value = FILTER_DECISION_ERROR;
                  }
                else
                  SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_NAME, target_option->getopt_option.name, input_value, usage_text);
                }
              }
            }
          else if ((*(ptr.integer_ptr)) != target_option->missing_value.integer_value)
            {
            *(ptr.integer_ptr) = target_option->missing_value.integer_value;
            changed_value = 1;

            if (current_settings->current_options->filter_grace < target_option->set_grace)
              current_settings->current_options->filter_grace = target_option->set_grace;

            if (return_value < target_option->set_consequence)
              return_value = target_option->set_consequence;
            }
          else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
            {
            SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_BAD_VALUE "\n", target_option->getopt_option.name, input_value);
            return_value = FILTER_DECISION_ERROR;
            }
          else
            SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_VALUE, target_option->getopt_option.name, input_value);
        else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
          {
          SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_UNKNOWN_OPTION "\n", target_option->getopt_option.name);
          return_value = FILTER_DECISION_ERROR;
          }
        else
          SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_UNKNOWN_OPTION, target_option->getopt_option.name);

        break;
      case CONFIG_TYPE_STRING_SINGLETON:
      case CONFIG_TYPE_FILE_SINGLETON:
      case CONFIG_TYPE_FILE_NOT_DIR_SINGLETON:
      case CONFIG_TYPE_DIR_SINGLETON:
      case CONFIG_TYPE_COMMAND_SINGLETON:
      case CONFIG_TYPE_OPTION_SINGLETON:
        if ((target_option->getter.get_string != NULL) &&
            ((ptr.string_ptr = (*(target_option->getter.get_string))(current_settings->current_options, 0)) != NULL))
          {
          input_value_ptr = (input_value != NULL) ? input_value : target_option->missing_value.string_value;
          if (input_value_ptr != NULL)
            {
            if (strcmp(input_value_ptr, CONFIG_VALUE_CANCEL) == 0)
              {
              if (*(ptr.string_ptr) != NULL)
                {
                if (((context & CONFIG_LOCATION_MASK_COPY_OPTIONS) == 0) ||
                    ((*(ptr.string_ptr)) != (*(*(target_option->getter.get_string))(&current_settings->base_options, 0))))
                  free(*(ptr.string_ptr));

                *(ptr.string_ptr) = NULL;
                }

              input_value_ptr = NULL;
              changed_value = 1;
              }
            else if (strncmp(input_value_ptr, CONFIG_VALUE_REMOVE, STRLEN(CONFIG_VALUE_REMOVE)) == 0)
              {
              if ((*(ptr.string_ptr) != NULL) &&
                  (strcmp(input_value_ptr + STRLEN(CONFIG_VALUE_REMOVE), *(ptr.string_ptr)) == 0))
                {
                if (((context & CONFIG_LOCATION_MASK_COPY_OPTIONS) == 0) ||
                    ((*(ptr.string_ptr)) != (*(*(target_option->getter.get_string))(&current_settings->base_options, 0))))
                  free(*(ptr.string_ptr));

                *(ptr.string_ptr) = NULL;
                }

              input_value_ptr = NULL;
              changed_value = 1;
              }

            if ((input_value_ptr != NULL) &&
                (((*(ptr.string_ptr)) == NULL) ||
                 (strcmp(*(ptr.string_ptr), input_value_ptr) != 0)))
              {
              tmp_int = strlen(input_value_ptr);

              if ((target_option->value_type == CONFIG_TYPE_DIR_SINGLETON) &&
                  (input_value_ptr[tmp_int - 1] == DIR_DELIMITER))
                tmp_int--;

              if ((target_option->validity.max_strlen > 0) &&
                  (tmp_int > target_option->validity.max_strlen))
                {
                SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_LENGTH, target_option->getopt_option.name, tmp_int, target_option->validity.max_strlen);
                tmp_int = target_option->validity.max_strlen;
                }

              if (((context & CONFIG_LOCATION_MASK_COPY_OPTIONS) != 0) &&
                  (*(ptr.string_ptr) != NULL) &&
                  ((*(ptr.string_ptr)) == (*(*(target_option->getter.get_string))(&current_settings->base_options, 0))))
                *(ptr.string_ptr) = NULL;

              if ((tmp_char = (char *)realloc(*(ptr.string_ptr), tmp_int + 1)) != NULL)
                {
                memcpy(tmp_char, input_value_ptr, sizeof(char) * tmp_int);
                tmp_char[tmp_int] = '\0';
                *(ptr.string_ptr) = tmp_char;
                changed_value = 1;

                if (current_settings->current_options->filter_grace < target_option->set_grace)
                  current_settings->current_options->filter_grace = target_option->set_grace;

                if (return_value < target_option->set_consequence)
                  return_value = target_option->set_consequence;
                }
              else
                {
                SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_MALLOC, (unsigned long)(sizeof(char) * (strlen(input_value_ptr) + 1)));
                return_value = FILTER_DECISION_ERROR;
                }
              }
            }
          else if ((*(ptr.string_ptr)) != NULL)
            {
            if (((context & CONFIG_LOCATION_MASK_COPY_OPTIONS) == 0) ||
                ((*(ptr.string_ptr)) != (*(*(target_option->getter.get_string))(&current_settings->base_options, 0))))
              free(*(ptr.string_ptr));

            *(ptr.string_ptr) = NULL;
            changed_value = 1;

            if (current_settings->current_options->filter_grace < target_option->set_grace)
              current_settings->current_options->filter_grace = target_option->set_grace;

            if (return_value < target_option->set_consequence)
              return_value = target_option->set_consequence;
            }
          else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
            {
            SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_BAD_VALUE "\n", target_option->getopt_option.name, input_value);
            return_value = FILTER_DECISION_ERROR;
            }
          else
            SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_VALUE, target_option->getopt_option.name, input_value);
          }
        else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
          {
          SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_UNKNOWN_OPTION "\n", target_option->getopt_option.name);
          return_value = FILTER_DECISION_ERROR;
          }
        else
          SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_UNKNOWN_OPTION, target_option->getopt_option.name);

        if (changed_value &&
            (target_option->value_type == CONFIG_TYPE_COMMAND_SINGLETON) &&
            ((*(ptr.string_ptr)) != NULL))
          for (i = 0; (*(ptr.string_ptr))[i] != '\0'; i++)
            if ((*(ptr.string_ptr))[i] == COMMAND_LINE_SPACER)
              (*(ptr.string_ptr))[i] = ' ';

        break;
      case CONFIG_TYPE_STRING_ARRAY:
      case CONFIG_TYPE_FILE_ARRAY:
      case CONFIG_TYPE_FILE_NOT_DIR_ARRAY:
      case CONFIG_TYPE_DIR_ARRAY:
      case CONFIG_TYPE_COMMAND_ARRAY:
      case CONFIG_TYPE_OPTION_ARRAY:
        if ((target_option->getter.get_string_array != NULL) &&
            ((ptr.string_array_ptr = (*(target_option->getter.get_string_array))(current_settings->current_options, 0)) != NULL))
          {
          input_value_ptr = (input_value != NULL) ? input_value : target_option->missing_value.string_value;
          if (input_value_ptr != NULL)
            {
            if (strcmp(input_value_ptr, CONFIG_VALUE_CANCEL) == 0)
              {
              if ((*(ptr.string_array_ptr)) != NULL)
                {
                if (((context & CONFIG_LOCATION_MASK_COPY_OPTIONS) == 0) ||
                    ((*(ptr.string_array_ptr)) != (*(*(target_option->getter.get_string_array))(&current_settings->base_options, 0))))
                  {
                  for (i = 0; (*(ptr.string_array_ptr))[i] != NULL; i++)
                    free((*(ptr.string_array_ptr))[i]);

                  free(*(ptr.string_array_ptr));
                  }

                *(ptr.string_array_ptr) = NULL;
                }

              input_value_ptr = NULL;
              changed_value = 1;
              }
            else if (strncmp(input_value_ptr, CONFIG_VALUE_REMOVE, STRLEN(CONFIG_VALUE_REMOVE)) == 0)
              {
              if ((*(ptr.string_array_ptr)) != NULL)
                {
                found_match = 0;

                for (i = 0; (*(ptr.string_array_ptr))[i] != NULL; i++)
                  if (!found_match)
                    {
                    if (strcmp(input_value_ptr + STRLEN(CONFIG_VALUE_REMOVE), (*(ptr.string_array_ptr))[i]) == 0)
                      {
                      if (((context & CONFIG_LOCATION_MASK_COPY_OPTIONS) == 0) ||
                          ((*(ptr.string_array_ptr)) != (*(*(target_option->getter.get_string_array))(&current_settings->base_options, 0))))
                        free((*(ptr.string_array_ptr))[i]);

                      (*(ptr.string_array_ptr))[i] = (*(ptr.string_array_ptr))[i + 1];

                      found_match = 1;
                      }
                    }
                  else
                    (*(ptr.string_array_ptr))[i] = (*(ptr.string_array_ptr))[i + 1];

                if ((*(ptr.string_array_ptr))[0] == NULL)
                  {
                  if (((context & CONFIG_LOCATION_MASK_COPY_OPTIONS) == 0) ||
                      ((*(ptr.string_array_ptr)) != (*(*(target_option->getter.get_string_array))(&current_settings->base_options, 0))))
                    free(*(ptr.string_array_ptr));

                  *(ptr.string_array_ptr) = NULL;
                  }
                }

              input_value_ptr = NULL;
              changed_value = 1;
              }

            if (input_value_ptr != NULL)
              {
              found_match = 0;

              if ((*(ptr.string_array_ptr)) != NULL)
                for (i = 0; (*(ptr.string_array_ptr))[i] != NULL; i++)
                  if (strcmp((*(ptr.string_array_ptr))[i], input_value_ptr) == 0)
                    {
                    found_match = 1;
                    break;
                    }

              if (!found_match)
                {
                tmp_int = strlen(input_value_ptr);

                while ((target_option->value_type == CONFIG_TYPE_DIR_ARRAY) &&
                       (tmp_int > 0) &&
                       (input_value_ptr[tmp_int - 1] == DIR_DELIMITER))
                  tmp_int--;

                if ((target_option->validity.max_strlen > 0) &&
                    (tmp_int > target_option->validity.max_strlen))
                  tmp_int = target_option->validity.max_strlen;

                if (((context & CONFIG_LOCATION_MASK_COPY_OPTIONS) != 0) &&
                    (*(ptr.string_array_ptr) != NULL) &&
                    ((tmp_base_string_array = (*(*(target_option->getter.get_string_array))(&current_settings->base_options, 0))) != NULL) &&
                    ((*(ptr.string_array_ptr)) == tmp_base_string_array))
                  {
                  *(ptr.string_array_ptr) = NULL;
                  for (i = 0; tmp_base_string_array[i] != NULL; i++)
                    if (!append_string(current_settings, ptr.string_array_ptr, tmp_base_string_array[i], strlen(tmp_base_string_array[i])))
                      {
                      return_value = FILTER_DECISION_ERROR;
                      break;
                      }
                  }

                if (return_value != FILTER_DECISION_ERROR)
                  {
                  if (append_string(current_settings, ptr.string_array_ptr, input_value_ptr, tmp_int))
                    {
                    changed_value = 1;

                    if (current_settings->current_options->filter_grace < target_option->set_grace)
                      current_settings->current_options->filter_grace = target_option->set_grace;

                    if (return_value < target_option->set_consequence)
                      return_value = target_option->set_consequence;
                    }
                  else
                    return_value = FILTER_DECISION_ERROR;
                  }
                }

              if (changed_value &&
                  (target_option->value_type == CONFIG_TYPE_COMMAND_ARRAY))
                {
                for (i = 0; (*(ptr.string_array_ptr))[i] != NULL; i++);
                if (i > 0)
                  for (j = 0; (*(ptr.string_array_ptr))[i - 1][j] != '\0'; j++)
                    if ((*(ptr.string_array_ptr))[i - 1][j] == COMMAND_LINE_SPACER)
                      (*(ptr.string_array_ptr))[i - 1][j] = ' ';
                }
              }
            }
          else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
            {
            SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_BAD_VALUE "\n", target_option->getopt_option.name, input_value);
            return_value = FILTER_DECISION_ERROR;
            }
          else
            SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_BAD_VALUE, target_option->getopt_option.name, input_value);
          }
        else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
          {
          SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_UNKNOWN_OPTION "\n", target_option->getopt_option.name);
          return_value = FILTER_DECISION_ERROR;
          }
        else
          SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_UNKNOWN_OPTION, target_option->getopt_option.name);

        break;
      default:
        break;
      }

  if (changed_value &&
      (target_option->additional_set_actions != NULL))
    return_value = (*(target_option->additional_set_actions))(current_settings, return_value, input_value, history);

  if (changed_value)
    target_option->value_set = 1;

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: FILTER_DECISION_ERROR
 *   SUCCESS: if values were set, the largest value from the appropriate spamdyke_option.  If no values were set, current_return_value
 */
int process_config_file(struct filter_settings *current_settings, char *config_filename, int current_return_value, int context, struct previous_action *history)
  {
  int return_value;
  FILE *tmp_file;
  int line_num;
  int i;
  int strlen_directive;
  int strlen_value;
  char tmp_buf[MAX_FILE_BUF + 1];
  char *buf_ptr;
  int strlen_buf;
  char directive[MAX_FILE_BUF + 1];
  char *current_directive;
  char value[MAX_FILE_BUF + 1];
  struct previous_action tmp_action;
  struct previous_action *current_action;
  int min_index;
  int max_index;
  int compare_result;
  union
    {
    int *integer_ptr;
    char **string_ptr;
    char ***string_array_ptr;
    } ptr;
  int num_config_file;
  int directive_pos;
  int value_pos;

  return_value = current_return_value;

  for (current_action = history; current_action != NULL; current_action = current_action->prev)
    if (!strcmp(config_filename, current_action->data))
      break;

  if (current_action == NULL)
    {
    tmp_action.data = config_filename;
    tmp_action.prev = history;
    current_action = &tmp_action;

    if ((tmp_file = fopen(config_filename, "r")) != NULL)
      {
      if (current_settings->current_options->config_file != NULL)
        for (num_config_file = 0; current_settings->current_options->config_file[num_config_file] != NULL; num_config_file++);
      else
        num_config_file = 0;

      line_num = 0;

      while (!feof(tmp_file) &&
             (line_num < MAX_FILE_LINES))
        {
        if ((fscanf(tmp_file, "%" STRINGIFY(MAX_FILE_BUF) "[^\r\n]%n", tmp_buf, &strlen_buf) == 1) &&
            (tmp_buf[0] != COMMENT_DELIMITER))
          {
          while ((strlen_buf > 0) &&
                 isspace((int)tmp_buf[strlen_buf - 1]))
            strlen_buf--;
          tmp_buf[strlen_buf] = '\0';

          buf_ptr = tmp_buf;
          while ((strlen_buf > 0) &&
                 isspace((int)buf_ptr[0]))
            {
            buf_ptr++;
            strlen_buf--;
            }

          if (strlen_buf > 0)
            {
            directive[0] = '\0';
            value[0] = '\0';

            if ((sscanf(buf_ptr, "%[^" VALUE_DELIMITER " \t\r\n]%*[ \t]%n" VALUE_DELIMITER "%*[ \t]%[^\r\n]%n", directive, &directive_pos, value, &value_pos) != 2) &&
                (sscanf(buf_ptr, "%[^" VALUE_DELIMITER " \t\r\n]%n" VALUE_DELIMITER "%*[ \t]%[^\r\n]%n", directive, &directive_pos, value, &value_pos) != 2) &&
                (sscanf(buf_ptr, "%[^" VALUE_DELIMITER " \t\r\n]%*[ \t]%n" VALUE_DELIMITER "%[^\r\n]%n", directive, &directive_pos, value, &value_pos) != 2))
              sscanf(buf_ptr, "%[^" VALUE_DELIMITER " \t\r\n]%n" VALUE_DELIMITER "%[^\r\n]%n", directive, &directive_pos, value, &value_pos);

            for (strlen_directive = 0; directive[strlen_directive] != '\0'; strlen_directive++)
              directive[strlen_directive] = tolower((int)directive[strlen_directive]);

            strlen_value = strlen(value);
            for (i = strlen_value - 1; i >= 0; i--)
              if (isspace((int)value[i]))
                value[i] = '\0';
              else
                break;

            for (i = ((value[0] == '\0') ? directive_pos : value_pos); i < strlen_buf; i++)
              if (!isspace((int)buf_ptr[i]))
                {
                if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
                  {
                  SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_SYNTAX_OPTION_FILE "\n", config_filename, line_num + 1, strlen_buf, buf_ptr);
                  return_value = FILTER_DECISION_ERROR;
                  }
                else
                  SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_SYNTAX_OPTION_FILE, config_filename, line_num + 1, strlen_buf, buf_ptr);

                break;
                }

            if (return_value != FILTER_DECISION_ERROR)
              {
              current_directive = directive;
              min_index = 0;
              max_index = current_settings->num_options - 1;
              while (max_index >= min_index)
                {
                i = ((max_index - min_index) / 2) + min_index;
                if ((compare_result = strcmp(current_directive, current_settings->option_list[i].getopt_option.name)) < 0)
                  max_index = i - 1;
                else if (compare_result > 0)
                  min_index = i + 1;
                else if ((current_settings->option_list[i].value_type == CONFIG_TYPE_ALIAS) &&
                         (current_settings->option_list[i].help_argument != NULL))
                  {
                  SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_ALIAS, current_directive, current_settings->option_list[i].help_argument, current_settings->option_list[i].help_argument);

                  current_directive = current_settings->option_list[i].help_argument;
                  min_index = 0;
                  max_index = current_settings->num_options - 1;
                  }
                else
                  {
                  if (current_settings->option_list[i].location & context)
                    {
                    SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_SET_VALUE_FROM_FILE, directive, config_filename, line_num + 1, value);
                    return_value = set_config_value(current_settings, context, &current_settings->option_list[i], value, return_value, current_action);
                    }
                  else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
                    {
                    SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_ILLEGAL_OPTION_FILE "\n", config_filename, line_num + 1, directive);
                    return_value = FILTER_DECISION_ERROR;
                    }
                  else
                    SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_ILLEGAL_OPTION_FILE, config_filename, line_num + 1, directive);

                  break;
                  }
                }

              if (min_index > max_index)
                {
                if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
                  {
                  SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_UNKNOWN_OPTION_FILE "\n", config_filename, line_num + 1, directive);
                  return_value = FILTER_DECISION_ERROR;
                  }
                else
                  SPAMDYKE_LOG_ERROR(current_settings, ERROR_CONFIG_UNKNOWN_OPTION_FILE, config_filename, line_num + 1, directive);
                }
              }
            }
          }

        /*
         * This defeats an "unused result" warning from gcc.
         * Ignoring this result here is perfectly safe.
         */
        i = fscanf(tmp_file, "%*1[\r\n]");
        line_num++;
        }

      fclose(tmp_file);

      if (return_value != FILTER_DECISION_ERROR)
        for (i = 0; current_settings->option_list[i].value_type != CONFIG_TYPE_NONE; i++)
          if ((current_settings->option_list[i].additional_actions != NULL) &&
              ((return_value = (*current_settings->option_list[i].additional_actions)(current_settings, return_value)) == FILTER_DECISION_ERROR))
            break;

      if (return_value != FILTER_DECISION_ERROR)
        {
        /*
         * If the value was cleared during configuration, it is reset to default.
         */
        for (i = 0; current_settings->option_list[i].value_type != CONFIG_TYPE_NONE; i++)
          switch (current_settings->option_list[i].value_type)
            {
            case CONFIG_TYPE_NAME_ONCE:
              if ((current_settings->option_list[i].getter.get_integer != NULL) &&
                  ((ptr.integer_ptr = (*(current_settings->option_list[i].getter.get_integer))(current_settings->current_options)) != NULL) &&
                  (*(ptr.integer_ptr) == 0))
                *(ptr.integer_ptr) = current_settings->option_list[i].default_value.integer_value;

              break;
            }

        if (current_settings->current_options->config_file != NULL)
          for (i = num_config_file; current_settings->current_options->config_file[i] != NULL; i++)
            {
            tmp_action.data = config_filename;
            tmp_action.prev = history;

            if ((return_value = process_config_file(current_settings, current_settings->current_options->config_file[i], return_value, context, &tmp_action)) == FILTER_DECISION_ERROR)
              break;
            }
        }
      }
    else if ((context & CONFIG_LOCATION_MASK_ERRORS_CRITICAL) != 0)
      {
      SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, LOG_ERROR_OPEN_CONFIG "\n", config_filename, strerror(errno));
      return_value = FILTER_DECISION_ERROR;
      }
    else
      SPAMDYKE_LOG_ERROR(current_settings, LOG_ERROR_OPEN_CONFIG, config_filename, strerror(errno));
    }

  return(return_value);
  }

/*
 * Return value:
 *   error: FILTER_DECISION_ERROR
 *   otherwise: return value from process_config_file()
 */
int process_config_dir(struct filter_settings *current_settings, char *target_dir, char *target_ip, char *target_name, char *target_sender_username, char *target_sender_domain, char *target_recipient_username, char *target_recipient_domain, int current_return_value, int *return_processed_file)
  {
  int return_value;
  int i;
  char tmp_path[4][MAX_BUF + 1];
  char ip_octets[4][4];
  int ip_ints[4];
  int strlen_path[4];
  struct stat tmp_stat;
  char *tmp_ptr;
  int processed_file[4];
  int found_sender_dir;
  int found_recipient_dir;

  return_value = current_return_value;
  found_sender_dir = 0;
  found_recipient_dir = 0;

  if (return_processed_file != NULL)
    for (i = 0; i < 4; i++)
      processed_file[i] = return_processed_file[i];
  else
    for (i = 0; i < 4; i++)
      processed_file[i] = 0;

  if (target_dir != NULL)
    {
    if ((return_value != FILTER_DECISION_ERROR) &&
        (!processed_file[0] ||
         ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_IP) != 0)) &&
        (target_ip != NULL))
      {
      snprintf(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_IP, target_dir);
      SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH_DIR, tmp_path[0]);

      if (stat(tmp_path[0], &tmp_stat) == 0)
        {
        if (S_ISDIR(tmp_stat.st_mode))
          {
          if ((sscanf(target_ip, "%3[0-9].%3[0-9].%3[0-9].%3[0-9]", ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]) == 4) &&
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
            strlen_path[0] = SNPRINTF(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_IP DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s", target_dir, ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]);
            strlen_path[1] = SNPRINTF(tmp_path[1], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_IP DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s", target_dir, ip_octets[0], ip_octets[1], ip_octets[2]);
            strlen_path[2] = SNPRINTF(tmp_path[2], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_IP DIR_DELIMITER_STR "%s" DIR_DELIMITER_STR "%s", target_dir, ip_octets[0], ip_octets[1]);
            strlen_path[3] = SNPRINTF(tmp_path[3], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_IP DIR_DELIMITER_STR "%s", target_dir, ip_octets[0]);

            for (i = 0; i < 4; i++)
              {
              SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH, tmp_path[i]);
              if (stat(tmp_path[i], &tmp_stat) == 0)
                {
                if (S_ISDIR(tmp_stat.st_mode))
                  {
                  return_value = process_config_dir(current_settings, tmp_path[i], NULL, target_name, target_sender_username, target_sender_domain, target_recipient_username, target_recipient_domain, return_value, processed_file);

                  if ((return_value == FILTER_DECISION_ERROR) ||
                      ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_IP) == 0))
                    break;
                  }
                else if (S_ISREG(tmp_stat.st_mode))
                  {
                  SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_FILE, tmp_path[i]);
                  return_value = process_config_file(current_settings, tmp_path[i], return_value, CONFIG_LOCATION_DIR, NULL);
                  print_configuration(current_settings);
                  processed_file[0] = 1;

                  if ((return_value == FILTER_DECISION_ERROR) ||
                      ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_IP) == 0))
                    break;
                  }
                }
              else if ((errno != ENOENT) &&
                       (errno != ENOTDIR))
                SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[i], strerror(errno));
              }
            }
          }
        }
      else if ((errno != ENOENT) &&
               (errno != ENOTDIR))
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[0], strerror(errno));
      }

    if ((return_value != FILTER_DECISION_ERROR) &&
        (!processed_file[1] ||
         ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_RDNS) != 0)) &&
        (target_name != NULL) &&
        ((strlen_path[2] = strlen(target_name)) > 0))
      {
      snprintf(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_NAME, target_dir);
      SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH_DIR, tmp_path[0]);

      if (stat(tmp_path[0], &tmp_stat) == 0)
        {
        if (S_ISDIR(tmp_stat.st_mode))
          {
          memcpy(tmp_path[2], target_name, sizeof(char) * MINVAL(strlen_path[2], MAX_BUF));
          tmp_path[2][MINVAL(strlen_path[2], MAX_BUF)] = '\0';

          strlen_path[1] = 0;
          tmp_path[1][0] = '\0';

          tmp_ptr = tmp_path[2] + strlen_path[2] - 1;
          while (tmp_ptr != tmp_path[2])
            {
            if (tmp_ptr[0] == '.')
              {
              snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], "%s" DIR_DELIMITER_STR, tmp_ptr + 1);
              strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);
              tmp_ptr[0] = '\0';
              }

            tmp_ptr--;
            }
          snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], "%s", tmp_ptr);
          strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);

          tmp_ptr = tmp_path[1] + strlen_path[1] - 1;
          while (tmp_path[1][0] != '\0')
            {
            strlen_path[0] = SNPRINTF(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_NAME DIR_DELIMITER_STR "%s", target_dir, tmp_path[1]);

            SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH, tmp_path[0]);
            if (stat(tmp_path[0], &tmp_stat) == 0)
              {
              if (S_ISDIR(tmp_stat.st_mode))
                {
                return_value = process_config_dir(current_settings, tmp_path[0], target_ip, NULL, target_sender_username, target_sender_domain, target_recipient_username, target_recipient_domain, return_value, processed_file);

                if ((return_value == FILTER_DECISION_ERROR) ||
                    ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_RDNS) == 0))
                  break;
                }
              else if (S_ISREG(tmp_stat.st_mode))
                {
                SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_FILE, tmp_path[0]);
                return_value = process_config_file(current_settings, tmp_path[0], return_value, CONFIG_LOCATION_DIR, NULL);
                print_configuration(current_settings);
                processed_file[1] = 1;

                if ((return_value == FILTER_DECISION_ERROR) ||
                    ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_RDNS) == 0))
                  break;
                }
              }
            else if ((errno != ENOENT) &&
                     (errno != ENOTDIR))
              SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[0], strerror(errno));

            while ((tmp_ptr > tmp_path[1]) &&
                   (tmp_ptr[0] != DIR_DELIMITER))
              tmp_ptr--;

            tmp_ptr[0] = '\0';
            }
          }
        }
      else if ((errno != ENOENT) &&
               (errno != ENOTDIR))
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[0], strerror(errno));
      }

    if ((return_value != FILTER_DECISION_ERROR) &&
        (!processed_file[2] ||
         ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_SENDER) != 0)) &&
        (target_sender_username != NULL) &&
        (target_sender_domain != NULL) &&
        ((strlen_path[2] = strlen(target_sender_domain)) > 0))
      {
      snprintf(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_SENDER, target_dir);
      SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH_DIR, tmp_path[0]);

      if (stat(tmp_path[0], &tmp_stat) == 0)
        {
        if (S_ISDIR(tmp_stat.st_mode))
          {
          found_sender_dir = 1;

          memcpy(tmp_path[2], target_sender_domain, sizeof(char) * MINVAL(strlen_path[2], MAX_BUF));
          tmp_path[2][MINVAL(strlen_path[2], MAX_BUF)] = '\0';

          strlen_path[1] = 0;
          tmp_path[1][0] = '\0';

          tmp_ptr = tmp_path[2] + strlen_path[2] - 1;
          while (tmp_ptr != tmp_path[2])
            {
            if (tmp_ptr[0] == '.')
              {
              snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], DIR_DELIMITER_STR "%s", tmp_ptr + 1);
              strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);
              tmp_ptr[0] = '\0';
              }

            tmp_ptr--;
            }

          snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], DIR_DELIMITER_STR "%s", tmp_path[2]);
          strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);

          strlen_path[0] = SNPRINTF(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_SENDER "%s" DIR_DELIMITER_STR CONFIG_DIR_USERNAME DIR_DELIMITER_STR "%s", target_dir, tmp_path[1], canonicalize_path(tmp_path[3], MAX_BUF, target_sender_username, -1));

          SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH, tmp_path[0]);
          if (stat(tmp_path[0], &tmp_stat) == 0)
            {
            if (S_ISDIR(tmp_stat.st_mode))
              return_value = process_config_dir(current_settings, tmp_path[0], target_ip, target_name, NULL, target_sender_domain, target_recipient_username, target_recipient_domain, return_value, processed_file);
            else if (S_ISREG(tmp_stat.st_mode))
              {
              SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_FILE, tmp_path[0]);
              return_value = process_config_file(current_settings, tmp_path[0], return_value, CONFIG_LOCATION_DIR, NULL);
              print_configuration(current_settings);
              processed_file[2] = 1;
              }
            }
          else if ((errno != ENOENT) &&
                   (errno != ENOTDIR))
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[0], strerror(errno));
          }
        }
      else if ((errno != ENOENT) &&
               (errno != ENOTDIR))
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[0], strerror(errno));
      }

    if ((return_value != FILTER_DECISION_ERROR) &&
        (!processed_file[2] ||
         ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_SENDER) != 0)) &&
        (target_sender_domain != NULL) &&
        ((strlen_path[2] = strlen(target_sender_domain)) > 0) &&
        found_sender_dir)
      {
      memcpy(tmp_path[2], target_sender_domain, sizeof(char) * MINVAL(strlen_path[2], MAX_BUF));
      tmp_path[2][MINVAL(strlen_path[2], MAX_BUF)] = '\0';

      strlen_path[1] = 0;
      tmp_path[1][0] = '\0';

      tmp_ptr = tmp_path[2] + strlen_path[2] - 1;
      while (tmp_ptr != tmp_path[2])
        {
        if (tmp_ptr[0] == '.')
          {
          snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], DIR_DELIMITER_STR "%s", tmp_ptr + 1);
          strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);
          tmp_ptr[0] = '\0';
          }

        tmp_ptr--;
        }

      snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], DIR_DELIMITER_STR "%s", tmp_path[2]);
      strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);

      tmp_ptr = tmp_path[1] + strlen_path[1] - 1;
      while (tmp_path[1][0] != '\0')
        {
        strlen_path[0] = SNPRINTF(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_SENDER "%s", target_dir, tmp_path[1]);

        SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH, tmp_path[0]);
        if (stat(tmp_path[0], &tmp_stat) == 0)
          {
          if (S_ISDIR(tmp_stat.st_mode))
            {
            return_value = process_config_dir(current_settings, tmp_path[0], target_ip, target_name, NULL, NULL, target_recipient_username, target_recipient_domain, return_value, processed_file);

            if ((return_value == FILTER_DECISION_ERROR) ||
                ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_SENDER) == 0))
              break;
            }
          else if (S_ISREG(tmp_stat.st_mode))
            {
            SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_FILE, tmp_path[0]);
            return_value = process_config_file(current_settings, tmp_path[0], return_value, CONFIG_LOCATION_DIR, NULL);
            print_configuration(current_settings);
            processed_file[2] = 1;

            if ((return_value == FILTER_DECISION_ERROR) ||
                ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_SENDER) == 0))
              break;
            }
          }
        else if ((errno != ENOENT) &&
                 (errno != ENOTDIR))
          SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[0], strerror(errno));

        while ((tmp_ptr >= tmp_path[1]) &&
               (tmp_ptr[0] != DIR_DELIMITER))
          tmp_ptr--;

        tmp_ptr[0] = '\0';
        }
      }

    if ((return_value != FILTER_DECISION_ERROR) &&
        (!processed_file[3] ||
         ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_RECIPIENT) != 0)) &&
        (target_recipient_username != NULL) &&
        (target_recipient_domain != NULL) &&
        ((strlen_path[2] = strlen(target_recipient_domain)) > 0))
      {
      snprintf(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_RECIPIENT, target_dir);
      SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH_DIR, tmp_path[0]);

      if (stat(tmp_path[0], &tmp_stat) == 0)
        {
        if (S_ISDIR(tmp_stat.st_mode))
          {
          found_recipient_dir = 1;

          memcpy(tmp_path[2], target_recipient_domain, sizeof(char) * MINVAL(strlen_path[2], MAX_BUF));
          tmp_path[2][MINVAL(strlen_path[2], MAX_BUF)] = '\0';

          strlen_path[1] = 0;
          tmp_path[1][0] = '\0';

          tmp_ptr = tmp_path[2] + strlen_path[2] - 1;
          while (tmp_ptr != tmp_path[2])
            {
            if (tmp_ptr[0] == '.')
              {
              snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], DIR_DELIMITER_STR "%s", tmp_ptr + 1);
              strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);
              tmp_ptr[0] = '\0';
              }

            tmp_ptr--;
            }

          snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], DIR_DELIMITER_STR "%s", tmp_path[2]);
          strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);

          strlen_path[0] = SNPRINTF(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_RECIPIENT "%s" DIR_DELIMITER_STR CONFIG_DIR_USERNAME DIR_DELIMITER_STR "%s", target_dir, tmp_path[1], canonicalize_path(tmp_path[3], MAX_BUF, target_recipient_username, -1));

          SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH, tmp_path[0]);
          if (stat(tmp_path[0], &tmp_stat) == 0)
            {
            if (S_ISDIR(tmp_stat.st_mode))
              return_value = process_config_dir(current_settings, tmp_path[0], target_ip, target_name, target_sender_username, target_sender_domain, NULL, target_recipient_domain, return_value, processed_file);
            else if (S_ISREG(tmp_stat.st_mode))
              {
              SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_FILE, tmp_path[0]);
              return_value = process_config_file(current_settings, tmp_path[0], return_value, CONFIG_LOCATION_DIR, NULL);
              print_configuration(current_settings);
              processed_file[3] = 1;
              }
            }
          else if ((errno != ENOENT) &&
                   (errno != ENOTDIR))
            SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[0], strerror(errno));
          }
        }
      else if ((errno != ENOENT) &&
               (errno != ENOTDIR))
        SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[0], strerror(errno));
      }

    if ((return_value != FILTER_DECISION_ERROR) &&
        (!processed_file[3] ||
         ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_RECIPIENT) != 0)) &&
        (target_recipient_domain != NULL) &&
        ((strlen_path[2] = strlen(target_recipient_domain)) > 0) &&
        found_recipient_dir)
      {
      memcpy(tmp_path[2], target_recipient_domain, sizeof(char) * MINVAL(strlen_path[2], MAX_BUF));
      tmp_path[2][MINVAL(strlen_path[2], MAX_BUF)] = '\0';

      strlen_path[1] = 0;
      tmp_path[1][0] = '\0';

      tmp_ptr = tmp_path[2] + strlen_path[2] - 1;
      while (tmp_ptr != tmp_path[2])
        {
        if (tmp_ptr[0] == '.')
          {
          snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], DIR_DELIMITER_STR "%s", tmp_ptr + 1);
          strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);
          tmp_ptr[0] = '\0';
          }

        tmp_ptr--;
        }

      strlen_path[1] += snprintf(tmp_path[1] + strlen_path[1], MAX_BUF - strlen_path[1], DIR_DELIMITER_STR "%s", tmp_path[2]);
      strlen_path[1] += strlen(tmp_path[1] + strlen_path[1]);

      tmp_ptr = tmp_path[1] + strlen_path[1] - 1;
      while (tmp_path[1][0] != '\0')
        {
        strlen_path[0] = SNPRINTF(tmp_path[0], MAX_BUF, "%s" DIR_DELIMITER_STR CONFIG_DIR_RECIPIENT "%s", target_dir, tmp_path[1]);

        SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_SEARCH, tmp_path[0]);
        if (stat(tmp_path[0], &tmp_stat) == 0)
          {
          if (S_ISDIR(tmp_stat.st_mode))
            {
            return_value = process_config_dir(current_settings, tmp_path[0], target_ip, target_name, target_sender_username, target_sender_domain, NULL, NULL, return_value, processed_file);

            if ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_RECIPIENT) == 0)
              break;
            }
          else if (S_ISREG(tmp_stat.st_mode))
            {
            SPAMDYKE_LOG_DEBUG(current_settings, LOG_DEBUG_CONFIG_FILE, tmp_path[0]);
            return_value = process_config_file(current_settings, tmp_path[0], return_value, CONFIG_LOCATION_DIR, NULL);
            print_configuration(current_settings);
            processed_file[3] = 1;

            if ((return_value == FILTER_DECISION_ERROR) ||
                ((current_settings->current_options->configuration_dir_search & CONFIG_DIR_SEARCH_ALL_RECIPIENT) == 0))
              break;
            }
          }
        else if ((errno != ENOENT) &&
                 (errno != ENOTDIR))
          SPAMDYKE_LOG_VERBOSE(current_settings, LOG_ERROR_STAT "%s: %s", tmp_path[0], strerror(errno));

        while ((tmp_ptr >= tmp_path[1]) &&
               (tmp_ptr[0] != DIR_DELIMITER))
          tmp_ptr--;

        tmp_ptr[0] = '\0';
        }
      }
    }

  if (return_processed_file != NULL)
    for (i = 0; i < 4; i++)
      return_processed_file[i] = processed_file[i];

  return(return_value);
  }

/*
 * Return value:
 *   FAILURE: FILTER_DECISION_ERROR
 *   SUCCESS: if values were set, the largest value from the appropriate spamdyke_option.  If no values were set, FILTER_DECISION_UNDECIDED
 */
int process_command_line(struct filter_settings *current_settings, int argc, char *argv[])
  {
  int return_value;
  int i;
  int opt;
  const char *current_directive;
  int compare_result;
  int min_index;
  int max_index;
  struct spamdyke_option *current_option;

  return_value = FILTER_DECISION_UNDECIDED;
  opterr = 0;

  while ((return_value != FILTER_DECISION_ERROR) &&
         ((opt = getopt_long(argc, argv, current_settings->short_options, current_settings->long_options, NULL)) != -1))
    if ((opt != '?') &&
        (opt != ':'))
      {
      current_option = NULL;

      if (current_settings->option_lookup[opt]->value_type == CONFIG_TYPE_ALIAS)
        {
        current_directive = current_settings->option_lookup[opt]->getopt_option.name;
        min_index = 0;
        max_index = current_settings->num_options - 1;
        while (max_index >= min_index)
          {
          i = ((max_index - min_index) / 2) + min_index;
          if ((compare_result = strcmp(current_directive, current_settings->option_list[i].getopt_option.name)) < 0)
            max_index = i - 1;
          else if (compare_result > 0)
            min_index = i + 1;
          else if ((current_settings->option_list[i].value_type == CONFIG_TYPE_ALIAS) &&
                   (current_settings->option_list[i].help_argument != NULL))
            {
            SPAMDYKE_LOG_EXCESSIVE(current_settings, LOG_DEBUGX_CONFIG_ALIAS, current_directive, current_settings->option_list[i].help_argument, current_settings->option_list[i].help_argument);

            current_directive = current_settings->option_list[i].help_argument;
            min_index = 0;
            max_index = current_settings->num_options - 1;
            }
          else
            {
            current_option = &current_settings->option_list[i];
            break;
            }
          }
        }
      else
        current_option = current_settings->option_lookup[opt];

      if (current_option != NULL)
        {
        if (current_settings->option_lookup[opt]->location & CONFIG_LOCATION_CMDLINE)
          return_value = set_config_value(current_settings, CONFIG_LOCATION_CMDLINE, current_option, optarg, return_value, NULL);
        else
          {
          SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_ILLEGAL_OPTION_CMDLINE "\n", argv[optind - 1]);
          return_value = FILTER_DECISION_ERROR;
          }
        }
      else
        {
        SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_UNKNOWN_OPTION "\n", argv[optind - 1]);
        return_value = FILTER_DECISION_ERROR;
        }
      }
    else
      {
      SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_UNKNOWN_OPTION "\n", argv[optind - 1]);
      return_value = FILTER_DECISION_ERROR;
      }

  if (return_value != FILTER_DECISION_ERROR)
    for (i = 0; current_settings->option_list[i].value_type != CONFIG_TYPE_NONE; i++)
      if ((current_settings->option_list[i].additional_actions != NULL) &&
          ((return_value = (*current_settings->option_list[i].additional_actions)(current_settings, return_value)) == FILTER_DECISION_ERROR))
        break;

  if (return_value == FILTER_DECISION_ERROR)
    exit(0);
  else if (optind < argc)
    current_settings->child_argv = argv + optind;
  else
    {
    SPAMDYKE_USAGE(current_settings, USAGE_LEVEL_SHORT, ERROR_CONFIG_NO_COMMAND "\n", NULL);
    exit(0);
    }

  return(return_value);
  }
