# -*- coding: binary -*-
# frozen_string_literal: true

module Rex
  module Proto
    module FTP
      #
      # FTP client class that wraps an already-authenticated FTP control channel socket.
      # Provides high-level methods for common FTP operations (PWD, CWD, LIST, RETR, STOR).
      # This is designed to be stored on an Msf::Sessions::FTP session instance.
      #
      class Client
        # @return [Rex::Socket::Tcp] The FTP control channel socket
        attr_accessor :sock

        # @return [String] The FTP server banner
        attr_reader :banner

        # @return [Rex::Socket::Tcp] The current data channel socket
        attr_accessor :datasocket

        # @return [Integer] Timeout in seconds for reading FTP responses
        attr_accessor :read_timeout

        # @return [Boolean] When true, print FTP commands and responses for debugging
        attr_accessor :trace

        # @return [Float, nil] Monotonic timestamp of the last interaction with the server
        attr_accessor :last_interaction

        # @param sock [Rex::Socket::Tcp] An already-authenticated FTP control socket
        # @param opts [Hash] Options hash
        # @option opts [Integer] :read_timeout (16) Timeout for reading FTP responses
        # @option opts [String] :banner The server banner received during initial connection
        # @option opts [Boolean] :trace (false) Enable FTP protocol tracing
        def initialize(sock, opts = {})
          @sock = sock
          @read_timeout = opts.fetch(:read_timeout, 16)
          @banner = opts.fetch(:banner, nil)
          @trace = opts.fetch(:trace, false)
          @datasocket = nil
          @ftpbuff = String.new
          @last_interaction = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        # @return [String] Remote host address
        def peerhost
          sock.peerhost
        end

        # @return [Integer] Remote port
        def peerport
          sock.peerport
        end

        # @return [String] "host:port"
        def peerinfo
          "#{peerhost}:#{peerport}"
        end

        # Send an FTP command and receive the response.
        #
        # @param args [Array<String>] Command and arguments, e.g. ['CWD', '/tmp']
        # @param recv [Boolean] Whether to wait for a response
        # @return [String] Server response
        def send_cmd(args, recv: true)
          @last_interaction = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          cmd = args.join(' ') + "\r\n"
          trace_send(cmd) if trace
          raw_send(cmd)
          if recv
            resp = recv_resp
            trace_recv(resp) if trace
            resp
          end
        end

        # Get current working directory via PWD.
        #
        # @return [String] Current directory path
        def pwd
          resp = send_cmd(['PWD'])
          if resp =~ /^257\s+"([^"]+)"/
            ::Regexp.last_match(1)
          else
            resp
          end
        end

        # Change directory via CWD.
        #
        # @param path [String] Target directory
        # @return [String] Server response
        def cwd(path)
          resp = send_cmd(['CWD', path])
          raise Rex::Proto::FTP::Error, resp if resp =~ /^[45]\d\d/

          resp
        end

        # List directory contents via LIST over data channel.
        #
        # @param path [String, nil] Optional path to list
        # @return [String] Raw directory listing
        def list(path = nil)
          dsock = data_connect
          raise Rex::Proto::FTP::Error, 'Failed to establish data channel' unless dsock

          args = path ? ['LIST', path] : ['LIST']
          resp = send_cmd(args)
          unless resp =~ /^(150|125)/
            data_disconnect
            raise Rex::Proto::FTP::Error, resp
          end

          data = read_data_channel
          data_disconnect
          wait_for_transfer_complete
          data
        end

        # Download file via RETR over data channel.
        #
        # @param remote_path [String] Remote file path
        # @return [String] File contents
        def get(remote_path)
          # Set binary mode
          send_cmd(['TYPE', 'I'])

          dsock = data_connect
          raise Rex::Proto::FTP::Error, 'Failed to establish data channel' unless dsock

          resp = send_cmd(['RETR', remote_path])
          unless resp =~ /^(150|125)/
            data_disconnect
            raise Rex::Proto::FTP::Error, resp
          end

          data = read_data_channel
          data_disconnect
          wait_for_transfer_complete
          data
        end

        # Upload file via STOR over data channel.
        #
        # @param remote_path [String] Remote file path
        # @param data [String] File data to upload
        # @return [String] Server response
        def put(remote_path, data)
          # Set binary mode
          send_cmd(['TYPE', 'I'])

          dsock = data_connect
          raise Rex::Proto::FTP::Error, 'Failed to establish data channel' unless dsock

          resp = send_cmd(['STOR', remote_path])
          unless resp =~ /^(150|125)/
            data_disconnect
            raise Rex::Proto::FTP::Error, resp
          end

          datasocket.put(data)
          data_disconnect
          wait_for_transfer_complete
        end

        # Read file contents. Alias for get, used by the cat command.
        #
        # @param remote_path [String] Remote file path
        # @return [String] File contents
        def read_file(remote_path)
          get(remote_path)
        end

        # Send QUIT and close the connection.
        def close
          begin
            send_cmd(['QUIT'], recv: false)
          rescue StandardError
            nil
          end
          begin
            sock.close
          rescue StandardError
            nil
          end
        end

        private

        # Establish a passive data channel connection via PASV.
        # Uses the control channel's peer host instead of the PASV-reported host,
        # since servers behind NAT often report unreachable internal addresses.
        #
        # @return [Rex::Socket::Tcp, nil] Data channel socket or nil on failure
        def data_connect
          datasocket.shutdown if datasocket
          self.datasocket = nil

          resp = send_cmd(['PASV'])

          # If we got a stale transfer-complete response from a previous data operation,
          # just read the next response — our PASV was already sent and the 227 should follow.
          if resp && resp =~ /^(226|250)\s/
            trace_info("Skipped stale response: #{resp.strip}") if trace
            resp = recv_resp
            trace_recv(resp) if trace
          end

          raise Rex::Proto::FTP::Error, "PASV failed: #{resp}" unless resp && resp =~ /^227/

          unless resp =~ /\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/
            raise Rex::Proto::FTP::Error, "Could not parse PASV response: #{resp}"
          end

          dataport = (::Regexp.last_match(5).to_i * 256) + ::Regexp.last_match(6).to_i
          trace_info("Data channel connecting to #{peerhost}:#{dataport}") if trace
          self.datasocket = Rex::Socket::Tcp.create(
            'PeerHost' => peerhost,
            'PeerPort' => dataport
          )
          trace_info('Data channel connected') if trace

          datasocket
        end

        # Close the data channel.
        def data_disconnect
          return unless datasocket

          begin
            datasocket.shutdown
          rescue StandardError
            nil
          end
          begin
            datasocket.close
          rescue StandardError
            nil
          end
          self.datasocket = nil
        end

        # Wait for the transfer-complete response (226/250) on the control channel.
        #
        # @return [String, nil] The transfer complete response
        def wait_for_transfer_complete
          resp = recv_resp
          trace_recv(resp) if trace && resp
          resp
        end

        # Read all available data from the data channel socket until the server closes it.
        #
        # @return [String] Data read from the data channel
        def read_data_channel
          data = String.new
          begin
            loop do
              chunk = datasocket.get_once(-1, 5)
              break unless chunk

              data << chunk
            end
          rescue ::IOError
            # Expected when transfer completes and server closes the data connection
          end
          data
        end

        # Read an FTP response from the control channel.
        # Handles multi-line responses (continuation lines where code is followed by '-').
        #
        # @return [String, nil] Response string or nil on timeout
        def recv_resp
          found_end = false
          resp = String.new
          left = String.new

          unless @ftpbuff.empty?
            left << @ftpbuff
            @ftpbuff = String.new
          end

          loop do
            if left.empty?
              data = sock.get_once(-1, read_timeout)
              unless data
                @ftpbuff << resp
                @ftpbuff << left
                return nil
              end
              got = data
            else
              got = left
              left = String.new
            end

            enlidx = got.rindex("\n")
            if enlidx && enlidx != (got.length - 1)
              left = String.new(got.slice!((enlidx + 1)..got.length))
            elsif enlidx.nil?
              left << got
              next
            end

            got.split(/\r?\n/).each do |ln|
              if !found_end
                resp << ln
                resp << "\r\n"
                found_end = true if ln.length > 3 && ln[3, 1] == ' '
              else
                left << ln
                left << "\r\n"
              end
            end

            if found_end
              @ftpbuff << left
              return resp
            end
          end
        end

        # Send raw data on the control channel.
        #
        # @param data [String] Data to send
        def raw_send(data)
          sock.put(data)
        end

        # Trace helpers for colored FTP protocol debugging output.
        # Colors: red for sent commands, blue for received responses, yellow for info.

        def trace_send(msg)
          warn "\e[1;31m>>>\e[0m \e[31m#{msg.strip}\e[0m"
        end

        def trace_recv(msg)
          warn "\e[1;34m<<<\e[0m \e[34m#{msg&.strip}\e[0m"
        end

        def trace_info(msg)
          warn "\e[1;33m***\e[0m \e[33m#{msg}\e[0m"
        end
      end

      # Error class for FTP protocol errors
      class Error < ::RuntimeError; end
    end
  end
end
