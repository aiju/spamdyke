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
#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include "spamdyke.h"

int append_string(struct filter_settings *current_settings, char ***target_list, char *target_string, int strlen_target_string);
int process_command_line(struct filter_settings *current_settings, int argc, char *argv[]);
int process_config_file(struct filter_settings *current_settings, char *config_filename, int current_return_value, int context, struct previous_action *history);
int process_config_dir(struct filter_settings *current_settings, char *target_dir, char *target_ip, char *target_name, char *target_sender_address, char *target_sender_domain, char *target_recipient_address, char *target_recipient_domain, int current_return_value, int *return_processed_file);
void free_string_array(char ***current_string_array, char **base_string_array);
void reset_current_options(struct filter_settings *current_settings, int *processed_file);
void free_current_options(struct filter_settings *current_settings, int *processed_file);
int copy_base_options(struct filter_settings *current_settings, int current_return_value);
int prepare_settings(int argc, char *argv[], char *envp[], int (*main_function)(struct filter_settings *, int, char **));
void print_configuration(struct filter_settings *current_settings);
void init_option_set(struct filter_settings *current_settings, struct option_set *target_options);

#endif /* CONFIGURATION_H */
