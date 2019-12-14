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
#include "spamdyke-qrv.h"

int check_path_perms(struct qrv_settings *current_settings, char *target_path, int type_flag, int permission_flags, struct stat *target_stat, int target_uid, int target_gid);
int find_command(char *input_text, char *return_text, int size_return_text);
int search_file(struct qrv_settings *current_settings, char *search_filename, char *target_string, int strlen_target_string, char start_wildcard, char *start_wildcard_matches, char end_wildcard, char *end_wildcard_matches);
int read_file(struct qrv_settings *current_settings, char *target_filename, char ***return_content, int start_index, int start_line, int end_line, int all_lines);
int read_file_first_line(struct qrv_settings *current_settings, char *target_filename, char **return_content);
char *reassemble_address(char *target_username, int strlen_username, char *target_domain, char *missing_data, char *return_address, int max_return_address, int *strlen_return_address);
int find_path_perms(struct qrv_settings *current_settings, char *target_path, int type_flag, int permission_flags, int target_uid, int target_gid);
int search_virtualdomains_file(struct qrv_settings *current_settings, char *search_filename, char *target_domain, int strlen_target_domain, char *return_entry, int *size_return_entry);

#endif /* SEARCH_FS_H */
