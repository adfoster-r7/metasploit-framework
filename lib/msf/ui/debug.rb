# -*- coding: binary -*-
# frozen_string_literal: true

module Msf
  module Ui
    ###
    #
    # Displays Metasploit information useful for Debugging.
    #
    ###
    module Debug
      COMMAND_HISTORY_TOTAL = 50
      ERROR_TOTAL = 10
      LOG_LINE_TOTAL = 50

      def self.issue_link
        return 'https://github.com/rapid7/metasploit-framework/issues/new'
      end

      def self.preamble
        return <<~PREMABLE
          Please provide the below information in any Github issues you open. New issues can be opened here #{get_issue_link}
          %red%undENSURE YOU HAVE REMOVED ANY SENSITIVE INFORMATION BEFORE SUBMITTING!%clr

          ===8<=== CUT AND PASTE EVERYTHING BELOW THIS LINE ===8<===


        PREMABLE
      end

      def self.all(framework, driver)
        all_information = preamble
        all_information += datastore(framework, driver)
        all_information += history
        all_information += errors
        all_information += logs
        all_information += versions(framework)

        all_information
      end

      def self.datastore(framework, driver)
        # Generate an ini with the existing config file
        ini = Rex::Parser::Ini.new(Msf::Config.config_file)

        # Delete all groups from the config ini that potentially have more up to date information
        ini.keys.each do |k|
          unless k =~ %r{^framework/database}
            ini.delete(k)
          end
        end

        # Retrieve and add more up to date information
        add_hash_to_ini_group(ini, framework.datastore, driver.get_config_core)
        add_hash_to_ini_group(ini, driver.get_config, driver.get_config_group)

        if driver.active_module
          ds = driver.active_module.datastore.dup

          # Ensures that the local default value of a variable isn't set if a global value of a variable is set
          ds.keys.each do |k|
            # Removes an active module datastore item if it has a default value & it matches the default value
            if driver.active_module.options.key?(k.upcase) && driver.active_module.options[k.upcase].default == ds[k]
              ds.delete(k)
            end
          end

          add_hash_to_ini_group(ini, ds, driver.active_module.refname)
        end

        if ini.to_s.empty?
          content = 'The local config file is empty, no global variables are set, and there is no active module.'
        else
          content = ini.to_s
        end

        build_section('Module/Datastore',
                      'The following global/module datastore, & databse setup was configured before the issue occurred:',
                      content)
      end

      def self.history
        end_pos = Readline::HISTORY.length - 1
        start_pos = end_pos > COMMAND_HISTORY_TOTAL ? end_pos - (COMMAND_HISTORY_TOTAL - 1) : 0

        commands = ''
        while start_pos <= end_pos
          # Formats command position in history to 6 characters in length
          commands += "#{'%-6.6s' % start_pos.to_s} #{Readline::HISTORY[start_pos]}\n"
          start_pos += 1
        end

        build_section('History',
                      'The following commands were ran before this issue occurred:',
                      commands)
      end

      def self.errors
        errors = File.read(File.join(Msf::Config.log_directory, 'error.log'))

        # Returns the errors in error.log file as an array
        # Separator of individual errors is two consecutive \n chars
        #
        # The below example errors will be captured as three separate errors (Any accompanying traces will also be captured):
        #
        # [05/15/2020 14:13:38] [e(0)] error: [-] Error during IRB: undefined method `[]' for nil:NilClass
        #
        #
        # [05/15/2020 14:19:20] [e(0)] error: [-] Error while running command debug: can't modify frozen String
        # Call stack:
        # /Users/Shared/Relocated_Items/Security/rapid7/metasploit-framework/lib/msf/ui/debug.rb:33:in `get_all'
        # /Users/Shared/Relocated_Items/Security/rapid7/metasploit-framework/lib/msf/ui/console/command_dispatcher/core.rb:318:in `cmd_debug'
        # /Users/Shared/Relocated_Items/Security/rapid7/metasploit-framework/lib/rex/ui/text/dispatcher_shell.rb:523:in `run_command'
        # /Users/Shared/Relocated_Items/Security/rapid7/metasploit-framework/lib/rex/ui/text/dispatcher_shell.rb:474:in `block in run_single'
        # /Users/Shared/Relocated_Items/Security/rapid7/metasploit-framework/lib/rex/ui/text/dispatcher_shell.rb:468:in `each'
        # /Users/Shared/Relocated_Items/Security/rapid7/metasploit-framework/lib/rex/ui/text/dispatcher_shell.rb:468:in `run_single'
        # /Users/Shared/Relocated_Items/Security/rapid7/metasploit-framework/lib/rex/ui/text/shell.rb:158:in `run'
        # /Users/Shared/Relocated_Items/Security/rapid7/metasploit-framework/lib/metasploit/framework/command/console.rb:48:in `start'
        # /Users/Shared/Relocated_Items/Security/rapid7/metasploit-framework/lib/metasploit/framework/command/base.rb:82:in `start'
        #
        #
        # [05/15/2020 14:23:55] [e(0)] error: [-] Error during IRB: undefined method `[]' for nil:NilClass
        res = errors.scan(%r|(\[\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\] \[[^\n]*?\] error:(?:(?!\n\n).)+)|m)

        if res.empty?
          return build_section('Errors',
                               'The following errors occurred before the issue occurred:',
                               'The error log file was empty')
        end

        # Scan returns each error as a single item array
        res.flatten!

        errors_str = concat_str_array_from_last_idx(res, ERROR_TOTAL, true)
        build_section('Errors',
                      'The following errors occurred before the issue occurred:',
                      errors_str)
      end

      def self.logs
        log_lines = File.readlines(File.join(Msf::Config.log_directory, 'framework.log'))

        logs_str = concat_str_array_from_last_idx(log_lines, LOG_LINE_TOTAL)

        build_section('Logs',
                      'The following logs were recorded before the issue occurred:',
                      logs_str)
      end

      def self.versions(framework)
        str = <<~VERSIONS
        Framework: #{framework.version}
        Ruby: #{RUBY_DESCRIPTION}
        Install Root: #{Msf::Config.install_root}
        Session Type: #{db_connection_info(framework)}
        Install Method: #{installation_method}
        VERSIONS

        build_section('Version/Install', 'The versions & install method of your Metasploit setup:', str)
      end

      class << self

        private

        def add_hash_to_ini_group(ini, hash, group_name)
          if hash.empty?
            return
          end

          unless ini.group?(group_name)
            ini.add_group(group_name)
          end

          hash.each_pair do |k, v|
            ini[group_name][k] = v
          end
        end

        def concat_str_array_from_last_idx(array, concat_total, extra_padding = false)
          start_pos = array.length > concat_total ? array.length - concat_total : 0
          end_pos = array.length - 1

          pad = extra_padding ? "\n\n" : ''
          str = array[start_pos..end_pos].join(pad)

          str.strip
        end

        # Copy pasta of the print_connection_info method in console/command_dispatcher/db.rb
        def db_connection_info(framework)
          unless framework.db.connection_established?
            return "#{framework.db.driver} selected, no connection"
          end

          cdb = ''
          if framework.db.driver == 'http'
            cdb = framework.db.name
          else
            ::ActiveRecord::Base.connection_pool.with_connection do |conn|
              if conn.respond_to?(:current_database)
                cdb = conn.current_database
              end
            end
          end

          if cdb.empty?
            output = "Connected Database Name could not be extracted. DB Connection type: #{framework.db.driver}."
          else
            output = "Connected to #{cdb}. Connection type: #{framework.db.driver}."
          end

          output += " Connection name: #{framework.db.get_data_service}." if framework.db.get_data_service

          output
        end

        def build_section(header_name, blurb, content)
          <<~SECTION
            ##  %grn#{header_name.strip}%clr
            #{blurb.strip}
            #{with_collapsible_wrapper(content.strip)}

          SECTION
        end

        def with_collapsible_wrapper(content)
          <<~WRAPPER
            <details>
            <summary>Collapse</summary>

            ```
            #{content}
            ```

            </details>
          WRAPPER
        end

        def installation_method
          if File.exist?(File.join(Msf::Config.install_root, 'version.yml'))
            'Omnibus Installer'
          elsif Msf::Config.install_root == File.join(File::SEPARATOR, 'usr', 'share', 'metasploit-framework')
            'Kali'
          elsif File.directory?(File.join(Msf::Config.install_root, '.git'))
            'Git Clone'
          else
            'Other'
          end
        end
      end
    end
  end
end
