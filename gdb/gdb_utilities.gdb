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

# Attaches to a VM that has paused at startup because -XX:+PauseAtStartup was
# given.
define attach_to_paused_vm
  shell ~/OpenJDKDiagTools/gdb/gen_gdb_attach_to_paused_vm_helper.sh gdb_attach_to_paused_vm_helper.gdb
  source gdb_attach_to_paused_vm_helper.gdb
end

# One column output version of x
define x1
  set $pos = (uintptr_t)$arg0
  set $len = $arg1
  while $len > 0
    x/1gx $pos
    set $pos += 8
    set $len -= 1
  end
end

define istate_with_fp
  set $_fp = (uintptr_t)$arg0
  set $istate = (frame::ijava_state*)($_fp - frame::ijava_state_size)
  printf "$istate = %p\n", $istate
  p/x *$istate
end

# istate relative to SP (R1)
define istate
  set $istate = &((frame::ijava_state*)(*(void**) $r1))[-1]
  printf "$istate = %p\n", $istate
  p/x *$istate
end

# Local Variables:
# mode: gdb-script
# End:
