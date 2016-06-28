#!/bin/bash

#######################################################################
# Copyright (c) 2014 ENEO Tecnología S.L.
# This file is part of redBorder.
# redBorder is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# redBorder is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License License for more details.
# You should have received a copy of the GNU Affero General Public License License
# along with redBorder. If not, see <http://www.gnu.org/licenses/>.
#######################################################################

manager=$1
mode=$2
rsakey=$3

function usage(){
  echo "$0 <manager_ip> <mode> [<identity_file>] "
}

#[ -f /opt/rb/etc/rb_sysconf.conf ] && source /opt/rb/etc/rb_sysconf.conf
#source /opt/rb/bin/rb_sysconf_common
#source /opt/rb/bin/rb_sysconf_base
#source /opt/rb/bin/rb_sysconf_system
#
#f_sys_init
#
#if [ "x$manager" != "x" -a "x$mode" != "x" ]; then
#  sys_ip_rb_manager=$join_cluster
#  #LANG=C /bin/date > /opt/rb/etc/cluster-installed.txt
#  f_sys_rb_register $manager $mode $rsakey
#else
#  usage
#fi

echo "f_sys_rb_register $manager $mode $rsakey"
logger "f_sys_rb_register $manager $mode $rsakey"
