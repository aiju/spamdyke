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
#ifndef EXEC_H
#define EXEC_H

#include "spamdyke.h"

int exec_path(struct filter_settings *current_settings, char *filename, char *argv[], char *envp[]);
int exec_checkpassword(struct filter_settings *current_settings, char *command_line, char *username, char *password, char *timestamp);
int exec_checkpassword_argv(struct filter_settings *current_settings, char *filename, char *argv[], char *username, char *password, char *timestamp);
int exec_command(struct filter_settings *current_settings, char *command_line, struct expect_send *protocol, char **return_content, int size_return_content, int *return_status);
int exec_command_argv(struct filter_settings *current_settings, char *filename, char *argv[], struct expect_send *protocol, char **return_content, int size_return_content, int *return_status);

#endif /* EXEC_H */
