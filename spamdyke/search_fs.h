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
#ifndef SEARCH_FS_H
#define SEARCH_FS_H

#include <sys/stat.h>
#include "spamdyke.h"

char *canonicalize_path(char *destination_buf, int maxlen_destination_buf, char *target_path, int strlen_target_path);
int find_path(struct filter_settings *current_settings, char *filename, char *envp[], char *return_filename, int size_return_filename);
int find_command(char *input_text, char *return_text, int size_return_text);
int examine_entry(char *target_string, int strlen_target_string, char *target_entry, int strlen_target_entry, char start_wildcard, char *start_wildcard_matches, char end_wildcard, char *end_wildcard_matches);
int search_file(struct filter_settings *current_settings, char *search_filename, char *target_string, int strlen_target_string, char start_wildcard, char *start_wildcard_matches, char end_wildcard, char *end_wildcard_matches);
int examine_tcprules_entry(struct filter_settings *current_settings, char *destination, int size_destination, char *target_entry, int strlen_target_entry, char *target_ip, char *target_name, int strlen_target_name);
int search_tcprules_file(struct filter_settings *current_settings, char *destination, int size_destination, char *search_filename, char *target_ip, char *target_name, int strlen_target_name);
char *search_domain_directory(struct filter_settings *current_settings, char *start_directory, char *target_domain, int strlen_target_domain);
int read_file(struct filter_settings *current_settings, char *target_filename, char ***return_content, int start_index, int start_line, int end_line, int all_lines);
int read_file_first_line(struct filter_settings *current_settings, char *target_filename, char **return_content);
int load_resolver_file(struct filter_settings *current_settings, char *target_filename, int *return_default_port);
char *reassemble_address(char *target_username, char *target_domain, char *missing_data, char *return_address, int max_return_address, int *strlen_return_address);
int examine_header(struct filter_settings *current_settings, char *target_header, int strlen_target_header, char *target_entry, int strlen_target_entry);
int search_header_file(struct filter_settings *current_settings, char *search_filename, char *target_header, int strlen_target_header);
int check_path_perms(struct filter_settings *current_settings, char *target_path, int type_flag, int permission_flags, struct stat *target_stat, int target_uid, int target_gid);

#endif /* SEARCH_FS_H */
