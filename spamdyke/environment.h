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
#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

char *find_environment_variable(struct filter_settings *current_settings, char **environment, char *target_variable, int strlen_target_variable, int *return_index);
void free_environment(char **original_envp, char ***target_envp, char **new_envp);
void free_environment_variable(char **original_envp, char ***target_envp, int target_index);
char *alloc_environment_variable(char **original_envp, char *target_variable, int new_size);
void print_current_environment(struct filter_settings *current_settings);

#endif /* ENVIRONMENT_H */
