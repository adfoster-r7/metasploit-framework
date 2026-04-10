# -*- coding: binary -*-

require 'English'
require 'rex/post/session_compatible_modules'

module Rex
  module Post
    module FTP
      module Ui
        ###
        #
        # This class provides a shell driven interface to the FTP client API.
        #
        ###
        class Console

          include Rex::Ui::Text::DispatcherShell
          include Rex::Post::SessionCompatibleModules

          # Dispatchers
          require 'rex/post/ftp/ui/console/command_dispatcher'
          require 'rex/post/ftp/ui/console/command_dispatcher/core'
          require 'rex/post/ftp/ui/console/command_dispatcher/client'

          #
          # Initialize the FTP console.
          #
          # @param [Msf::Sessions::FTP] session
          def initialize(session)
            # The FTP client context
            self.session = session
            self.client = session.client
            prompt = '%undFTP%clr'
            history_file = Msf::Config.history_file_for_session_type(session_type: session.type, interactive: false)
            super(prompt, '>', history_file, nil, :ftp)

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(Rex::Post::FTP::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(Rex::Post::FTP::Ui::Console::CommandDispatcher::Client)
            enstack_dispatcher(Msf::Ui::Console::CommandDispatcher::LocalFileSystem)

            # Set up logging to whatever logsink 'core' is using
            if !$dispatcher['ftp']
              $dispatcher['ftp'] = $dispatcher['core']
            end
          end

          #
          # Called when someone wants to interact with the FTP client. It's
          # assumed that init_ui has been called prior.
          #
          def interact(&block)
            # Run queued commands
            commands.delete_if do |ent|
              run_single(ent)
              true
            end

            # Run the interactive loop
            run do |line|
              # Run the command
              run_single(line)

              # If a block was supplied, call it, otherwise return false
              if block
                block.call
              else
                false
              end
            end
          end

          #
          # Queues a command to be run when the interactive loop is entered.
          #
          def queue_cmd(cmd)
            commands << cmd
          end

          #
          # Runs the specified command wrapper in something to catch
          # exceptions.
          #
          def run_command(dispatcher, method, arguments)
            super
          rescue Timeout::Error
            log_error('Operation timed out.')
          rescue Rex::InvalidDestination => e
            log_error(e.message)
          rescue ::Errno::EPIPE, ::OpenSSL::SSL::SSLError, ::IOError => e
            # Only kill the session if the control channel is dead
            begin
              session.client.sock.peerinfo
              # Control channel is still alive, this was a data channel error
              log_error("#{e.class} #{e.message}")
            rescue ::StandardError
              session.kill
            end
          rescue Rex::Proto::FTP::Error => e
            log_error(e.message.to_s)
            elog(e)
          rescue ::StandardError => e
            log_error("Error running command #{method}: #{e.class} #{e}")
            elog(e)
          end

          # @param [Hash] opts
          # @return [String]
          def help_to_s(opts = {})
            super + format_session_compatible_modules
          end

          #
          # Logs that an error occurred and persists the callstack.
          #
          def log_error(msg)
            print_error(msg)

            elog(msg, 'ftp')

            dlog("Call stack:\n#{$ERROR_POSITION.join("\n")}", 'ftp')
          end

          # @return [Msf::Sessions::FTP]
          attr_reader :session

          # @return [Rex::Proto::FTP::Client]
          attr_reader :client

          def format_prompt(val)
            substitute_colors("%undFTP%clr (#{session.address}) > ", true)
          end

          protected

          attr_writer :session, :client # :nodoc:
          attr_accessor :commands # :nodoc:
        end
      end
    end
  end
end
