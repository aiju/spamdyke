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
#ifndef FILTER_H
#define FILTER_H

#include "spamdyke.h"

int filter_rdns_missing(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf);
int filter_ip_in_rdns_cc(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf);
int filter_rdns_whitelist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_rdns_whitelist_file(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_rdns_whitelist_dir(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_rdns_blacklist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_rdns_blacklist_file(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_rdns_blacklist_dir(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_ip_whitelist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_ip_blacklist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_ip_in_rdns_blacklist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_ip_in_rdns_whitelist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_rdns_resolve(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf);
int filter_dns_rwl(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_dns_rhswl(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_dns_rbl(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_dns_rhsbl(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_earlytalker(struct filter_settings *current_settings, int initial_connection, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf);
int filter_sender_whitelist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_sender_rhswl(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_sender_blacklist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_sender_rhsbl(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_level(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf);
int filter_sender(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, int strlen_target_domain);
int filter_recipient_whitelist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection);
int filter_recipient_max(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf);
int filter_recipient_blacklist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_recipient_graylist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf);
int filter_recipient(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf);
int filter_header_blacklist(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf);
int filter_recipient_valid(struct filter_settings *current_settings, int *target_action, int *return_action_locked, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *target_reason_buf, int size_target_reason_buf, int strlen_recipient_username, int strlen_recipient_domain);
void reset_rejection(struct filter_settings *current_settings, int rejection_index, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *input_reason, char *target_reason_buf, int size_target_reason_buf);
void set_rejection(struct filter_settings *current_settings, int rejection_index, struct rejection_data **target_rejection, struct rejection_data *target_rejection_buf, char *target_message_buf, int size_target_message_buf, char *append_message, char *input_reason, char *target_reason_buf, int size_target_reason_buf);

#endif /* FILTER_H */
