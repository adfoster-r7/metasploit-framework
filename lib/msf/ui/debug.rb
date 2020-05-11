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
      ISSUE_LINK = 'https://r-7.co/msf-issue'
      BANNER = "\nPlease provide the below information in any Github issues you open. New issues can be opened here #{ISSUE_LINK}\n"+
        "%red%undENSURE YOU HAVE REMOVED ANY SENSITIVE INFORMATION BEFORE SUBMITTING!%clr\n\n"
      COMMAND_HISTORY_TOTAL = 50
      ERROR_TOTAL = 10
      LOG_LINE_TOTAL = 50

      def self.set_driver(driver)
        @@driver ||= driver
      end

      def self.set_framework(framework)
        @@framework ||= framework
      end

      def self.get_banner
        return BANNER.dup
      end

      def self.get_issue_link
        return ISSUE_LINK.dup
      end

      def self.get_all
        all_information = "" + BANNER
        all_information << get_datastore
        all_information << get_history
        all_information << get_errors
        all_information << get_logs
        all_information << get_versions

        all_information
      end

      def self.get_history
        end_pos = (Readline::HISTORY.length) -1
        start_pos = end_pos > COMMAND_HISTORY_TOTAL ? end_pos - (COMMAND_HISTORY_TOTAL - 1) : 0

        commands = ""
        while start_pos <= end_pos
          # Formats command position in history to 6 characters in length
          commands += "#{'%-6.6s' % start_pos.to_s} #{Readline::HISTORY[start_pos]}\n"
          start_pos += 1
        end

        build_banner('History') + commands + "\n"
      end

      def self.get_datastore
        # Generate an ini with the existing config file
        ini = Rex::Parser::Ini.new(Msf::Config.config_file)

        # Delete all groups from the config ini that potentially have more up to date information
        ini.keys.each do |k|
          unless k =~ /^framework\/database/
            ini.delete(k)
          end
        end

        # Retrieve and add more up to date information
        add_hash_to_ini_group(ini, @@framework.datastore, @@driver.get_config_core)
        add_hash_to_ini_group(ini, @@driver.get_config, @@driver.get_config_group)

        if @@driver.active_module
          ds = @@driver.active_module.datastore.dup

          # Ensures that the local default value of a variable isn't set if a global value of a variable is set
          ds.keys.each do |k|
            # Removes an active module datastore item if it has a default value & it matches the default value
            if @@driver.active_module.options.key?(k.upcase) && @@driver.active_module.options[k.upcase].default == ds[k]
              ds.delete(k)
            end
          end

          add_hash_to_ini_group(ini, ds, @@driver.active_module.refname)
        end

        banner = build_banner('Datastore')

        if ini.to_s.empty?
          banner + "The local config file is empty, no global variables are set, and there is no active module.\n\n"
        else
          banner + ini.to_s
        end
      end

      def self.get_errors
        errors = File.read(Msf::Config.log_directory + File::SEPARATOR + "error.log")

        #Returns the errors in error.log file as an array | Separator of errors is two consecutive \n chars
        res = errors.scan(/(\[\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d\] \[.*?\] error:(?:(?!\n\n).)+)/m)

        #Scan returns each error as a single item array
        res.flatten!
        #Scan reverses initial LIFO order of +errors+
        res.reverse!

        build_banner('Errors') + concat_str_array_from_last_idx(res, ERROR_TOTAL, true)
      end

      def self.get_logs
        log_lines = File.readlines(Msf::Config.log_directory + File::SEPARATOR + "framework.log")

        build_banner('Logs') + concat_str_array_from_last_idx(log_lines, LOG_LINE_TOTAL)
      end

      def self.get_versions
        require 'pry'
        binding.pry

        major, minor, patch = @@framework.version.split('-')

        str = ""
        str += "Framework Major Version: #{major} \n"
        str += "Framework Minor Version: #{minor} \n"
        str += "Framework Patch Version: #{patch} \n"
        str += "Ruby Version: #{RUBY_DESCRIPTION} \n"
        str += "DB Session Status: #{get_db_connection_info} \n"

        build_banner('Versions') + str
      end

      #######
      private
      #######

      def self.add_hash_to_ini_group(ini, hash, group_name)
        if hash.empty?
          return
        end

        unless ini.group?(group_name)
          ini.add_group(group_name)
        end

        hash.each_pair do |k,v|
          ini[group_name][k] = v
        end
      end

      def self.concat_str_array_from_last_idx(array, concat_total, extra_padding=false)
        end_pos = array.length > concat_total ? array.length - concat_total : 0
        start_pos = array.length - 1

        str = ""
        while start_pos >= end_pos
          str += array[start_pos]
          str += "\n\n" if extra_padding
          start_pos -= 1
        end

        str.strip + "\n\n"
      end

      def self.build_banner(banner_name)
        str =  "###########################################\n"
        str += "%grn#{banner_name}%clr" + "\n"
        str += "###########################################\n\n"

        str
      end

      #Copy pasta of the print_connection_info method in console/command_dispatcher/db.rb
      def self.get_db_connection_info
        cdb = ''
        if @@framework.db.driver == 'http'
          cdb = @@framework.db.name
        else
          ::ActiveRecord::Base.connection_pool.with_connection do |conn|
            if conn.respond_to?(:current_database)
              cdb = conn.current_database
            end
          end
        end
        output = "Connected to #{cdb}. Connection type: #{@@framework.db.driver}."
        output += " Connection name: #{@@framework.db.get_data_service}." if @@framework.db.get_data_service

        output
      end
    end
  end
end
