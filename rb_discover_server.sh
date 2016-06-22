#!/bin/bash

source /etc/profile.f/rvm.sh

rvm gemset use rb-discover

rb_discover_server.rb $*
