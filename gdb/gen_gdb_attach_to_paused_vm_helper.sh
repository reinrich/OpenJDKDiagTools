#!/bin/bash

#
# Copyright (c) 2021 Richard Reingruber. All rights reserved.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

#
# Helper script for do_attached_to_paused_vm in gdb_utilities.gdb
#
# Finds and reads vm.paused.$VMPID that is generated if the VM is started with
# -XX:+PauseAtStartup.  Generates a helper script with name given as $1. The
# caller (do_attached_to_paused_vm) sources this script and therby attaches to
# the paused VM. The file vm.paused.$VMPID is deleted which signals the VM to
# continue execution.
#

PAUSED_FILE_PREFIX=vm.paused.
OUTPUT_FILE=$1

[ -f ${PAUSED_FILE_PREFIX}* ] || { echo 'printf "ERROR: vm.paused.* file not found\n"' > $OUTPUT_FILE ; exit 1 ; }

VMPID=$(ls ${PAUSED_FILE_PREFIX}*)
VMPID=${VMPID#$PAUSED_FILE_PREFIX}


cat > $OUTPUT_FILE <<EOF
printf "attaching to VM with PID $VMPID \n"
attach $VMPID
shell rm ${PAUSED_FILE_PREFIX}${VMPID}
EOF
