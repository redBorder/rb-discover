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

source /etc/profile.d/redBorder*
source /etc/profile.d/rvm.sh

USER="rb-discover"
GROUP="${USER}"
PID=$(ps aux|grep -i rb_discover_server.rb | grep -v grep | grep ruby | grep -v vim | awk '{print $2}')

if [ "x$PID" != "x" ]; then
  echo "rb-discover is already running. Killing it before starting the service ( $PID)"
  kill -9 $PID
fi

mkdir -p /var/log/rb-discover
chown -R ${USER}:${USER} /var/log/rb-discover

cd /opt/rb/var/rb-discover/bin
exec chpst -P -u ${USER} -U ${USER} ./rb_discover_server.rb -o

