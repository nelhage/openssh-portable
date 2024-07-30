#!/bin/sh
# Copyright (c) 2000-2020 Synology Inc. All rights reserved.

LOGGER="/usr/bin/logger"

# /var/empty must be owned by root and not group or world-writable.
check_empty_dir() {
	local privsep_path='/var/empty'

	if [ ! -d "${privsep_path}" ]; then
		/bin/mkdir -p -m755 "${privsep_path}"
	elif [ "$(stat -c %a ${privsep_path})" != "755" ]; then
		/bin/chmod 755 "${privsep_path}"
	fi
}

# It is required that your private key files are NOT accessible by others.
check_sshkey_perm() {
	local DEF_KEY_PERM='600'
	local DEF_PUB_KEY_PERM='644'
	local sshkey_prefix='/etc/ssh/ssh_host_'
	local ori_perm

	for sshkey in ${sshkey_prefix}*_key; do
		ori_perm="$(stat -c %a "${sshkey}")"
		if [ $? -eq 0 ] && [ "${ori_perm}" != "${DEF_KEY_PERM}" ]; then
			${LOGGER} -p warn "correct ${sshkey} permission from ${ori_perm} to ${DEF_KEY_PERM}"
			/bin/chmod "${DEF_KEY_PERM}" "${sshkey}"
		fi
	done
	for sshkey_pub in ${sshkey_prefix}*_key.pub; do
		ori_perm="$(stat -c %a "${sshkey_pub}")"
		if [ $? -eq 0 ] && [ "${ori_perm}" != "${DEF_PUB_KEY_PERM}" ]; then
			${LOGGER} -p warn "correct ${sshkey_pub} permission from ${ori_perm} to ${DEF_PUB_KEY_PERM}"
			/bin/chmod "${DEF_PUB_KEY_PERM}" "${sshkey_pub}"
		fi
	done
}

check_empty_dir
check_sshkey_perm
