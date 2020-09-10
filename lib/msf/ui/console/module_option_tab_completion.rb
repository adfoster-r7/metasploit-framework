module Msf
  module Ui
    module Console
      ###
      #
      # Module-specific tab completion helper.
      #
      ###
      module ModuleOptionTabCompletion
        #
        # Tab completion for the unset command
        #
        # @param str [String] the string currently being typed before tab was hit
        # @param words [Array<String>] the previously completed words on the command
        #   line. `words` is always at least 1 when tab completion has reached this
        #   stage since the command itself has been completed.
        def cmd_unset_tabs(str, words)
          datastore = active_module ? active_module.datastore : self.framework.datastore
          datastore.keys
        end
        #
        # Tab completion options values
        #
        def tab_complete_option(str, words)
          if str.end_with?("=")
            option_name = str.chop()
            ::Readline.completion_append_character = " "
            return tab_complete_option_values(option_name, words, opt: option_name).map { |value| "#{str}#{value}"}
          else
            if str.include?("=")
              str_split = str.split("=")
              option_value = str_split[1].strip
              option_name = str_split[0].strip
              ::Readline.completion_append_character = " "
              return tab_complete_option_values(option_value, words, opt: option_name).map { |value| "#{option_name}=#{value}"}
            end
          end
          ::Readline.completion_append_character = ''
          return tab_complete_option_names(str, words).map { |name| "#{name}=" }
        end
        #
        # Provide tab completion for name values
        #
        def tab_complete_option_names(str, words)
          res = cmd_unset_tabs(str, words) || [ ]
          # There needs to be a better way to register global options, but for
          # now all we have is an ad-hoc list of opts that the shell treats
          # specially.
          res += %w{
            ConsoleLogging
            LogLevel
            MinimumRank
            SessionLogging
            TimestampOutput
            Prompt
            PromptChar
            PromptTimeFormat
            MeterpreterPrompt
          }
          mod = active_module
          if (not mod)
            return res
          end
          mod.options.sorted.each { |e|
            name, _opt = e
            res << name
          }
          # Exploits provide these three default options
          if (mod.exploit?)
            res << 'PAYLOAD'
            res << 'NOP'
            res << 'TARGET'
            res << 'ENCODER'
          elsif (mod.evasion?)
            res << 'PAYLOAD'
            res << 'TARGET'
            res << 'ENCODER'
          elsif (mod.payload?)
            res << 'ENCODER'
          end
          if mod.kind_of?(Msf::Module::HasActions)
            res << "ACTION"
          end
          if ((mod.exploit? or mod.evasion?) and mod.datastore['PAYLOAD'])
            p = framework.payloads.create(mod.datastore['PAYLOAD'])
            if (p)
              p.options.sorted.each { |e|
                name, _opt = e
                res << name
              }
            end
          end
          unless str.blank?
            res = res.select { |term| term.upcase.start_with?(str.upcase) }
            res = res.map { |term|
              if str == str.upcase
                str + term[str.length..-1].upcase
              elsif str == str.downcase
                str + term[str.length..-1].downcase
              else
                str + term[str.length..-1]
              end
            }
          end
          return res
        end
        #
        # Provide tab completion for option values
        #
        def tab_complete_option_values(str, words, opt:)
          res = []
          mod = active_module
          # With no active module, we have nothing to compare
          if (not mod)
            return res
          end
          # Well-known option names specific to exploits
          if (mod.exploit?)
            return option_values_payloads() if opt.upcase == 'PAYLOAD'
            return option_values_targets()  if opt.upcase == 'TARGET'
            return option_values_nops()     if opt.upcase == 'NOPS'
            return option_values_encoders() if opt.upcase == 'STAGEENCODER'
          elsif (mod.evasion?)
            return option_values_payloads() if opt.upcase == 'PAYLOAD'
            return option_values_targets()  if opt.upcase == 'TARGET'
          end
          # Well-known option names specific to modules with actions
          if mod.kind_of?(Msf::Module::HasActions)
            return option_values_actions() if opt.upcase == 'ACTION'
          end
          # The ENCODER option works for evasions, payloads and exploits
          if ((mod.evasion? or mod.exploit? or mod.payload?) and opt.upcase == 'ENCODER')
            return option_values_encoders()
          end
          # Well-known option names specific to post-exploitation
          if (mod.post? or mod.exploit?)
            return option_values_sessions() if opt.upcase == 'SESSION'
          end
          # Is this option used by the active module?
          mod.options.each_key do |key|
            if key.downcase == opt.downcase
              res.concat(option_values_dispatch(mod.options[key], str, words))
            end
          end
          # How about the selected payload?
          if ((mod.evasion? or mod.exploit?) and mod.datastore['PAYLOAD'])
            if p = framework.payloads.create(mod.datastore['PAYLOAD'])
              p.options.each_key do |key|
                res.concat(option_values_dispatch(p.options[key], str, words)) if key.downcase == opt.downcase
              end
            end
          end
          return res
        end
        #
        # Provide possible option values based on type
        #
        def option_values_dispatch(o, str, words)
          res = []
          res << o.default.to_s if o.default
          case o
          when Msf::OptAddress
            case o.name.upcase
            when 'RHOST'
              option_values_target_addrs().each do |addr|
                res << addr
              end
            when 'LHOST', 'SRVHOST', 'REVERSELISTENERBINDADDRESS'
              rh = self.active_module.datastore['RHOST'] || framework.datastore['RHOST']
              if rh and not rh.empty?
                res << Rex::Socket.source_address(rh)
              else
                res += tab_complete_source_address
                res += tab_complete_source_interface(o)
              end
            end
          when Msf::OptAddressRange
            case str
            when /^file:(.*)/
              files = tab_complete_filenames($1, words)
              res += files.map { |f| "file:" + f } if files
            when /\/$/
              res << str+'32'
              res << str+'24'
              res << str+'16'
            when /\-$/
              res << str+str[0, str.length - 1]
            else
              option_values_target_addrs().each do |addr|
                res << addr
              end
            end
          when Msf::OptPort
            case o.name.upcase
            when 'RPORT'
              option_values_target_ports().each do |port|
                res << port
              end
            end
            if (res.empty?)
              res << (rand(65534)+1).to_s
            end
          when Msf::OptEnum
            o.enums.each do |val|
              res << val
            end
          when Msf::OptPath
            files = tab_complete_filenames(str, words)
            res += files if files
          when Msf::OptBool
            res << 'true'
            res << 'false'
          when Msf::OptString
            if (str =~ /^file:(.*)/)
              files = tab_complete_filenames($1, words)
              res += files.map { |f| "file:" + f } if files
            end
          end
          return res
        end
        # XXX: We repurpose OptAddressLocal#interfaces, so we can't put this in Rex
        def tab_complete_source_interface(o)
          return [] unless o.is_a?(Msf::OptAddressLocal)
          o.interfaces
        end
        #
        # Provide valid payload options for the current exploit
        #
        def option_values_payloads
          if @cache_payloads && active_module == @previous_module && active_module.target == @previous_target
            return @cache_payloads
          end
          @previous_module = active_module
          @previous_target = active_module.target
          @cache_payloads = active_module.compatible_payloads.map do |refname, payload|
            refname
          end
          @cache_payloads
        end
        #
        # Provide valid session options for the current post-exploit module
        #
        def option_values_sessions
          if active_module.respond_to?(:compatible_sessions)
            active_module.compatible_sessions.map { |sid| sid.to_s }
          end
        end
        #
        # Provide valid target options for the current exploit
        #
        def option_values_targets
          res = []
          if (active_module.targets)
            1.upto(active_module.targets.length) { |i| res << (i-1).to_s }
            res += active_module.targets.map(&:name)
          end
          return res
        end
        #
        # Provide valid action options for the current module
        #
        def option_values_actions
          res = []
          if (active_module.actions)
            active_module.actions.each { |i| res << i.name }
          end
          return res
        end
        #
        # Provide valid nops options for the current exploit
        #
        def option_values_nops
          framework.nops.map { |refname, mod| refname }
        end
        #
        # Provide valid encoders options for the current exploit or payload
        #
        def option_values_encoders
          framework.encoders.map { |refname, mod| refname }
        end
        #
        # Provide the target addresses
        #
        def option_values_target_addrs
          res = [ ]
          res << Rex::Socket.source_address()
          return res if not framework.db.active
          # List only those hosts with matching open ports?
          mport = self.active_module.datastore['RPORT']
          if mport
            mport = mport.to_i
            hosts = {}
            framework.db.services.each do |service|
              if service.port == mport
                hosts[ service.host.address ] = true
              end
            end
            hosts.keys.each do |host|
              res << host
            end
            # List all hosts in the database
          else
            framework.db.hosts.each do |host|
              res << host.address
            end
          end
          return res
        end
        #
        # Provide the target ports
        #
        def option_values_target_ports
          res = [ ]
          return res if not framework.db.active
          return res if not self.active_module.datastore['RHOST']
          host = framework.db.has_host?(framework.db.workspace, self.active_module.datastore['RHOST'])
          return res if not host
          framework.db.services.each do |service|
            if service.host_id == host.id
              res << service.port.to_s
            end
          end
          return res
        end
      end
    end
  end
end