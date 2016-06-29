require "socket"
require "timeout"

module UDPPing
    @drone_udp_port = 8071
    @buffer_size    = 10240
    @broadcast      = `ip a s bond1 2>/dev/null|grep brd|grep inet|head -n 1 | awk '{print $4}'`
    
    
    def self.answer_client(ip, port, response)
        s = UDPSocket.new
        s.send(Marshal.dump(response), 0, ip, port)
        s.close
    end
    
    def self.start_service_announcer(server_udp_port, &code)
        Thread.fork do
            s = UDPSocket.new
            s.bind('0.0.0.0', server_udp_port)
            
            loop do
              body, sender = s.recvfrom(@buffer_size)
              data = Marshal.load(body)
              client_ip   = sender[3]
              client_port = data[:reply_port]
              response = code.call(data[:content], client_ip)
            
              if response
                begin
                  answer_client(client_ip, client_port, response)
                rescue
                  # Make sure thread does not crash
                end
              end
            end
        end
    end
    
    def self.broadcast_to_potential_servers(content, broadcast, udp_port)
        broadcast = '<broadcast>' if (broadcast.nil? or broadcast=="")
        body = {:reply_port => @drone_udp_port, :content => content}
        
        s = UDPSocket.new
        s.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
        s.send(Marshal.dump(body), 0, broadcast, udp_port)
        s.close
    end
    
    def self.start_server_listener(time_out=5, &code)
        Thread.fork do
            s = UDPSocket.new
            s.bind('0.0.0.0', @drone_udp_port)
            
            begin
                body, sender = timeout(time_out) { s.recvfrom(@buffer_size) }
                server_ip = sender[3]
                data = Marshal.load(body)
                code.call(data, server_ip)
                s.close
            rescue Timeout::Error
                s.close
                raise
            end
        end
    end
    
    def self.query_server(content, server_ip, server_udp_port, time_out=5, &code)
        thread = start_server_listener(time_out) do |data, server_ip|
            code.call(data, server_ip)
        end
        
        broadcast_to_potential_servers(content, server_ip.nil? ? `ip a s bond1 2>/dev/null|grep brd|grep inet|head -n 1 | awk '{print $4}'`.chomp : server_ip , server_udp_port)
        
        begin
            thread.join
        rescue Timeout::Error
            return false
        end
        true
    end

end

## vim:ts=4:sw=4:expandtab:ai:nowrap:formatoptions=croqln:
