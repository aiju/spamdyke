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
#ifndef CONFIG_TEST_H
#define CONFIG_TEST_H

#include <sys/stat.h>
#include "spamdyke.h"

#ifndef WITHOUT_CONFIG_TEST

int config_test_file_read(struct filter_settings *current_settings, char *target_file, char *option_name, char *start_message, char *success_message, char *failure_message, char *failure_overlength_message, int line_recommendation, char *failure_overrecommendation_message);
int config_test_file_write(struct filter_settings *current_settings, char *target_file, char *option_name, char *start_message, char *success_message, char *failure_message);
int config_test_file_read_write(struct filter_settings *current_settings, char *target_file, char *option_name, char *start_message, char *success_message, char *failure_message, char *failure_overlength_message, int line_recommendation, char *failure_overrecommendation_message);
int config_test_file_execute(struct filter_settings *current_settings, char *target_file, char *option_name, char *start_message, char *success_message, char *failure_message, struct stat *target_stat);
int config_test_dir_read(struct filter_settings *current_settings, char *target_dir, char *option_name, char *start_message, char *success_message, char *failure_message);
int config_test_dir_write(struct filter_settings *current_settings, char *target_dir, char *option_name, char *start_message, char *success_message, char *failure_message_create, char *failure_message_delete);
int config_test_spamdyke_binary(struct filter_settings *current_settings, int argc, char *argv[]);

#endif /* WITHOUT_CONFIG_TEST */

int config_test_noop(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_graylist(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_rdns_dir(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_smtpauth(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_tls_certificate(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_tls_privatekey(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_tls_password(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_tls_dhparams(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_relay_level(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_configuration_dir(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_cdb(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test_qmail_option(struct filter_settings *current_settings, struct spamdyke_option *target_option);
int config_test(struct filter_settings *current_settings, int argc, char *argv[]);

#endif /* CONFIG_TEST_H */
