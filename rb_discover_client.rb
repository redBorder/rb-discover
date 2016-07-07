#!/usr/bin/env ruby

#######################################################################
## Copyright (c) 2014 ENEO Tecnología S.L.
## This file is part of redBorder.
## redBorder is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
## redBorder is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Affero General Public License License for more details.
## You should have received a copy of the GNU Affero General Public License License
## along with redBorder. If not, see <http://www.gnu.org/licenses/>.
########################################################################

require "prettyprint"
require 'getopt/std'
require 'yaml'
require 'json'
require 'tempfile'
require 'netaddr'
require 'symmetric-encryption'
require 'system/getifaddrs'
require 'arp_scan'

require File.join(ENV['RBDIR'].nil? ? '/usr/lib/redborder' : ENV['RBDIR'],'lib/udp_ping')

SERVER_LISTEN_PORT = 8070
RANDOM_STR=rand(36**32).to_s(36)
CLUSTERFILE="/etc/redborder/cluster-installed.txt"
CLIENTPEM="/etc/chef/client.pem"
USERDATA="/var/lib/cloud/instance/user-data.txt"

discover_net = nil
discover_dev = nil

# Try to initialize Encryption
if File.exist?USERDATA
    File.open(USERDATA).each do |line|
        unless line.match(/^\s*DISCOVER_KEY=(?<key>[^\s]*)\s*$/).nil?
            SymmetricEncryption.cipher = SymmetricEncryption::Cipher.new(:key=>line.match(/^\s*DISCOVER_KEY=(?<key>[^\s]*)\s*$/)[:key],:cipher_name => 'aes-128-cbc')
        end
        unless line.match(/^\s*DISCOVER_NET=(?<key>[^\s]*)\s*$/).nil?
            discover_net = line.match(/^\s*DISCOVER_NET=(?<net>[^\s]*)\s*$/)[:net]
        end
    end
end

# Initialize network device
unless discover_net.nil?
    System.get_all_ifaddrs.each do |netdev|
        if IPAddr.new(discover_net).include?(netdev[:inet_addr])
            discover_dev = netdev
        end
    end
end

cdomain = File.read("/etc/redborder/cdomain").split("\n").first if File.exist?"/etc/redborder/cdomain"
cdomain="redborder.cluster" if cdomain.nil? or cdomain==""

def usage()
  printf("INFO: rb_discover_client.rb [-h][-r <ip>][-s][-c][-m] \n")
  printf("   -h       print this help\n")
  printf("   -r <ip>  connect to remote server (unicast) instead of broadcast\n")
  printf("   -s       quiet mode. Show only server\n")
  printf("   -m       do no create master\n")
  printf("   -f       force\n")
  printf("   -c       auto-config. Discover remote server and try to connect if it is available\n")
  exit 1
end

opt = Getopt::Std.getopts("hscr:mf")
usage if opt["h"]
autoconfig=opt["c"]

# Check if node is configured yet
if opt["c"] and File.exists?CLUSTERFILE and File.exists?CLIENTPEM and opt["f"].nil?
    p "This node is already configured!!"
    exit 1
end

server_data={}
counter=1
max_counter=600
final_chef_server=opt["r"]
ret_code=0
forcefinish=false

p "Querying server (#{final_chef_server.nil? ? "broadcast" : final_chef_server }) ..." if opt["s"].nil?

while server_data["installed"]!=true and server_data["ready"]!=true and counter<max_counter and !forcefinish
    client_data={"hello"=> RANDOM_STR, "only_ready" => final_chef_server.nil?, "hostname" => `hostname -s`.chomp, "cdomain" => cdomain}.to_json
    # Query to discover server
    result = UDPPing.query_server(client_data, final_chef_server, SERVER_LISTEN_PORT) do |data, server_ip|
        if final_chef_server.nil?
            p "redBorder server founded on #{server_ip}" if opt["s"].nil?
            final_chef_server=server_ip
        end
        if autoconfig.nil? # Non Auto-config
            # In this mode, we will print some information and a return code that explains what kind of manager we had found
            if opt["s"]
                puts "#{data["chef_server"]}\n"
            else
                puts "#{data}\n"
            end
            if data["master"] or data["chef_server"] or data["installed"] or data["ready"]
                ret_code=0
            elsif data["mode"].nil? or data["mode"] == "core" or data["mode"] == "coreriak" or data["mode"] == "coreplus" or data["mode"] == "corezk" or data["mode"]=="master"
                ret_code=2
            else
                ret_code=3
            end
        else # Auto-config
            if data["client_msg"]==client_data # check for data integrity
                if data["installed"] and data["ready"] and data["chef_server"]
                    # found a manager in master mode
                    if File.exists?'/etc/redborder/manager_mode'
                        default_mode = File.open('/etc/redborder/manager_mode', &:readline).strip
                    elsif File.exists?'/etc/chef/initialrole'
                        default_mode = File.open('/etc/chef/initialrole', &:readline).strip
                    else
                        default_mode = "nginx"
                    end
                    
                    # we need to setup as nginx if my default mode is master due to founded a master in the network
                    default_mode="nginx" if default_mode=="master"

                    forcefinish=true # we found finally a master, no needs to going on
                    system("name=$(hostname); [ \"x$name\" == \"xrbmanager\" ] && hostname \"rb#{rand(36**10).to_s(36)}\" ") # setting hostname to an auto-hostname different from default

                    # we need to save the RSA key provided by the master
                    file = Tempfile.new('rb_discover_client')
                    File.open(file.path, 'w') { |file| file.write(data["private_rsa"])}
          
                    # Node register using rb_cluster_register.sh with the provided RSA key
                    system("ldconfig; source /etc/profile.d/redBorder-* /etc/profile.d/rvm.sh; /usr/bin/rb_cluster_register.sh '#{data["chef_server"]}' '#{default_mode}' #{file.path}")
                    file.close
                    file.unlink
                end
            else
                p "ERROR: invalid hello message from #{server_ip}"
            end
        end
    end # end do code from UDPPing.query_server

    if autoconfig.nil? # Non Auto-config
        counter=max_counter # better make a break?
    elsif !forcefinish
        if result or !final_chef_server.nil?
            # we have founded redBorder server. checking if it is ready
            s=rand(1..6)*5
            if File.exist?CLUSTERFILE and File.exists?CLIENTPEM
                # It is configured already. We don't need to wait
                counter=max_counter
            elsif final_chef_server.nil?
                sleep s
            else
                p "Waiting for #{final_chef_server} to become active (#{counter}/#{max_counter}). Sleeping #{s} seconds"
                sleep s
            end
        else
            # We haven't found any master
            # We try to detect using arp scan
            create_master=true

            #if File.exists?"/usr/bin/arp-scan"
            if File.exists?'/etc/redborder/manager_mode'
                local_mode = File.open('/etc/redborder/manager_mode', &:readline).strip
            elsif File.exists?'/etc/chef/initialrole'
                local_mode = File.open('/etc/chef/initialrole', &:readline).strip
            else
                local_mode = "core"
            end

            begin
                if discover_net.nil?
                    netbond = `ip a s bond1 2>/dev/null|grep brd|grep inet|head -n 1 | awk '{print $2}'`.chomp
                else
                    netbond = discover_dev[:inet_addr]
                end
                if netbond!=""
                    netbond=NetAddr::CIDR.create(netbond)
                    p "Scanning network via ARP request"
                    #ips=`/usr/bin/arp-scan -x -q -I bond1 #{netbond.to_s} | awk '{print $1}'`.split("\n")
                    report_arpscan = ARPScan("-I bond1 #{netbond.to_s}")
                    found=false
                    candidates=[]
                    allcandidates=[]

                    allcandidates << NetAddr::CIDR.create(netbond.ip).to_i
                    candidates << NetAddr::CIDR.create(netbond.ip).to_i if (local_mode=="core" or local_mode=="coreriak" or local_mode=="coreplus" or local_mode=="corezk" or local_mode=="master")

                    report_arpscan.hosts.each do |host|
                        if !found
                            system("/usr/bin/rb_discover_client.rb -r #{host.ip_addr}")
                            discover_ret=$?.exitstatus
                            if discover_ret == 0
                                # founded a master node
                                p "Founded redBorder node on #{host.ip_addr}"
                                final_chef_server=host.ip_addr
                                found=true
                                create_master=false
                            elsif discover_ret == 2
                                # founded a core node ... posible candidate
                                candidates << NetAddr::CIDR.create(host.ip_addr).to_i
                                allcandidates << NetAddr::CIDR.create(host.ip_addr).to_i
                            elsif discover_ret == 3
                                # founded normal node
                                allcandidates << NetAddr::CIDR.create(host.ip_addr).to_i
                            end
                        end
                    end

                    candidates = allcandidates if candidates.size == 0

                    if !found and candidates.size>1
                        if candidates.sort.first == NetAddr::CIDR.create(netbond.ip).to_i
                            # if we are the first in te list of candidates, we are the new master
                            create_master=true
                        else
                            # the first candidate in the list will be the new chef server
                            final_chef_server=NetAddr::CIDR.create(candidates.sort.first).ip
                            create_master=false
                        end
                    end
                end
            rescue
                create_master=true
            end
            #end

            # Master node configuration
            if create_master
                counter=max_counter
                if opt["m"].nil?
                    p "Configuring local redBorder instance as master ...."
                    system("/usr/bin/rb_configure_master.sh -f")
                    File.delete("/etc/redborder/cluster.lock") if File.exists?"/etc/redborder/cluster.lock"
                    system("service chef-client start")
                    p "The instance will be configured in background"
                    p "Review /var/log/chef-client/current to see the process"
                else
                    p "This node would be configured as master (dry run)"
                end
            end
        end
    end
    counter=counter+1
end

p "Query finished. Result: #{result}" if opt["s"].nil?

exit result ? ret_code : 1

## vim:ts=4:sw=4:expandtab:ai:nowrap:formatoptions=croqln:
