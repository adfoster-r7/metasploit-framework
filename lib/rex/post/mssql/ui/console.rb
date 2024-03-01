# -*- coding: binary -*-

require 'rex/post/sql/ui/console'

module Rex
  module Post
    module MSSQL
      module Ui
        ###
        #
        # This class provides a shell driven interface to the MSSQL client API.
        #
        ###
        class Console
          include Rex::Post::Sql::Ui::Console
          include Rex::Ui::Text::DispatcherShell

          # Dispatchers
          require 'rex/post/mssql/ui/console/command_dispatcher'
          require 'rex/post/mssql/ui/console/command_dispatcher/core'
          require 'rex/post/mssql/ui/console/command_dispatcher/client'

          #
          # Initialize the MSSQL console.
          #
          # @param [Msf::Sessions::MSSQL] session
          def initialize(session, opts={})
            # The mssql client context
            self.session = session
            self.client = session.client
            envchange = ::Rex::Proto::MSSQL::ClientMixin::ENVCHANGE
            prompt = "%undMSSQL @ #{client.sock.peerinfo} (#{client.initial_info_for_envchange(envchange: envchange::DATABASE)[:new]})%clr"
            history_manager = Msf::Config.mssql_session_history
            super(prompt, '>', history_manager, nil, :mssql)

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(::Rex::Post::MSSQL::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(::Rex::Post::MSSQL::Ui::Console::CommandDispatcher::Client)

            # Set up logging to whatever logsink 'core' is using
            if ! $dispatcher['mssql']
              $dispatcher['mssql'] = $dispatcher['core']
            end
          end

          # @return [Msf::Sessions::MSSQL]
          attr_reader :session

          # @return [MSSQL::Client]
          attr_reader :client

          # @return [String]
          def database_name
            session.client.query('SELECT DB_NAME();')[:rows][0][0]
          end

          # @param [Object] val
          # @return [String]
          def format_prompt(val)
            prompt = "%undMSSQL @ #{client.sock.peerinfo} (#{database_name})%clr > "
            substitute_colors(prompt, true)
          end

          protected

          attr_writer :session, :client # :nodoc:
          attr_accessor :commands # :nodoc:
        end
      end
    end
  end
end
