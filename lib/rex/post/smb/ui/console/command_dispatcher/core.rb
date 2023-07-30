# -*- coding: binary -*-

module Rex
module Post
module SMB
module Ui

###
#
# Core SMB client commands
#
###
class Console::CommandDispatcher::Core

  include Rex::Post::SMB::Ui::Console::CommandDispatcher

  #
  # Initializes an instance of the core command set using the supplied session and client
  # for interactivity.
  #
  # @param [Rex::Post::SMB::Ui::Console] console
  def initialize(console)
    super
  end

  @@irb_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help menu.'             ],
    '-e' => [true,  'Expression to evaluate.']
  )

  #
  # List of supported commands.
  #
  def commands
    cmds = {
      '?'                        => 'Help menu',
      'background'               => 'Backgrounds the current session',
      'bg'                       => 'Alias for background',
      'exit'                     => 'Terminate the SMB session',
      'help'                     => 'Help menu',
      'irb'                      => 'Open an interactive Ruby shell on the current session',
      'pry'                      => 'Open the Pry debugger on the current session',
      'sessions'                 => 'Quickly switch to another session',
    }

    reqs = {
    }

    filter_commands(cmds, reqs)
  end

  #
  # Core
  #
  def name
    'Core'
  end

  def cmd_sessions_help
    print_line('Usage: sessions <id>')
    print_line
    print_line('Interact with a different session Id.')
    print_line('This works the same as calling this from the MSF shell: sessions -i <session id>')
    print_line
  end

  def cmd_sessions(*args)
    if args.length == 0 || args[0].to_i == 0
      cmd_sessions_help
    elsif args[0].to_s == client.name.to_s
      print_status("Session #{client.name} is already interactive.")
    else
      print_status("Backgrounding session #{client.name}...")
      # store the next session id so that it can be referenced as soon
      # as this session is no longer interacting
      client.next_session = args[0]
      client.interacting = false
    end
  end

  def cmd_background_help
    print_line('Usage: background')
    print_line
    print_line('Stop interacting with this session and return to the parent prompt')
    print_line
  end

  def cmd_background
    # TODO: client is ruby_smb so doesn't have a name, and session isn't available in this context
    # print_status("Backgrounding session #{client.name}...")
    print_status("Backgrounding session...")
    session.interacting = false
  end

  alias cmd_bg cmd_background
  alias cmd_bg_help cmd_background_help

  #
  # Terminates the SMB session.
  #
  def cmd_exit(*args)
    print_status('Shutting down SMB... TODO properly disconnect/close socket etc')
    # client.core.shutdown rescue nil
    # client.shutdown_passive_dispatcher
    shell.stop
  end

  def cmd_irb_help
    print_line('Usage: irb')
    print_line
    print_line('Open an interactive Ruby shell on the current session.')
    print @@irb_opts.usage
  end

  def cmd_irb_tabs(str, words)
    return [] if words.length > 1
    @@irb_opts.option_keys
  end

  #
  # Open an interactive Ruby shell on the current session
  #
  def cmd_irb(*args)
    expressions = []

    # Parse the command options
    @@irb_opts.parse(args) do |opt, idx, val|
      case opt
      when '-e'
        expressions << val
      when '-h'
        return cmd_irb_help
      end
    end

    session = self.session
    framework = session.framework

    if expressions.empty?
      print_status('Starting IRB shell...')
      # TODO: What are the semantics of session vs client for SMB?
      print_status("You are in the \"client\" (session) object\n")
      Rex::Ui::Text::Shell::HistoryManager.with_context(name: :irb) do
        Rex::Ui::Text::IrbShell.new(session).run
      end
    else
      # XXX: No vprint_status here
      if framework.datastore['VERBOSE'].to_s == 'true'
        print_status("You are executing expressions in #{binding.receiver}")
      end

      expressions.each { |expression| eval(expression, binding) }
    end
  end

  def cmd_pry_help
    print_line 'Usage: pry'
    print_line
    print_line 'Open the Pry debugger on the current session.'
    print_line
  end

  #
  # Open the Pry debugger on the current session
  #
  def cmd_pry(*args)
    if args.include?('-h')
      cmd_pry_help
      return
    end

    begin
      require 'pry'
    rescue LoadError
      print_error('Failed to load Pry, try "gem install pry"')
      return
    end

    print_status('Starting Pry shell...')
    print_status("You are in the \"client\" (session) object\n")

    Pry.config.history_load = false
    Rex::Ui::Text::Shell::HistoryManager.with_context(history_file: Msf::Config.pry_history, name: :pry) do
      client.pry
    end
  end

  # def cmd_info_help
  #   print_line('Usage: info <module>')
  #   print_line
  #   print_line('Prints information about a post-exploitation module')
  #   print_line
  # end
  #
  # #
  # # Show info for a given Post module.
  # #
  # # See also +cmd_info+ in lib/msf/ui/console/command_dispatcher/core.rb
  # #
  # def cmd_info(*args)
  #   return unless msf_loaded?
  #
  #   if args.length != 1 or args.include?('-h')
  #     cmd_info_help
  #     return
  #   end
  #
  #   module_name = args.shift
  #   mod = client.framework.modules.create(module_name);
  #
  #   if mod.nil?
  #     print_error("Invalid module: #{module_name}")
  #   end
  #
  #   if (mod)
  #     print_line(::Msf::Serializer::ReadableText.dump_module(mod))
  #     mod_opt = ::Msf::Serializer::ReadableText.dump_options(mod, '   ')
  #     print_line("\nModule options (#{mod.fullname}):\n\n#{mod_opt}") if (mod_opt and mod_opt.length > 0)
  #   end
  # end
  #
  # def cmd_info_tabs(str, words)
  #   tab_complete_modules(str, words) if msf_loaded?
  # end

  # def cmd_resource_help
  #   print_line "Usage: resource path1 [path2 ...]"
  #   print_line
  #   print_line "Run the commands stored in the supplied files. (- for stdin, press CTRL+D to end input from stdin)"
  #   print_line "Resource files may also contain ERB or Ruby code between <ruby></ruby> tags."
  #   print_line
  # end
  #
  # def cmd_resource(*args)
  #   if args.empty?
  #     cmd_resource_help
  #     return false
  #   end
  #
  #   args.each do |res|
  #     good_res = nil
  #     if res == '-'
  #       good_res = res
  #     elsif ::File.exist?(res)
  #       good_res = res
  #     elsif
  #       # let's check to see if it's in the scripts/resource dir (like when tab completed)
  #       [
  #         ::Msf::Config.script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter',
  #         ::Msf::Config.user_script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter'
  #       ].each do |dir|
  #         res_path = dir + ::File::SEPARATOR + res
  #         if ::File.exist?(res_path)
  #           good_res = res_path
  #           break
  #         end
  #       end
  #     end
  #     if good_res
  #       client.console.load_resource(good_res)
  #     else
  #       print_error("#{res} is not a valid resource file")
  #       next
  #     end
  #   end
  # end
  #
  # def cmd_resource_tabs(str, words)
  #   tabs = []
  #   #return tabs if words.length > 1
  #   if ( str and str =~ /^#{Regexp.escape(::File::SEPARATOR)}/ )
  #     # then you are probably specifying a full path so let's just use normal file completion
  #     return tab_complete_filenames(str,words)
  #   elsif (not words[1] or not words[1].match(/^\//))
  #     # then let's start tab completion in the scripts/resource directories
  #     begin
  #       [
  #         ::Msf::Config.script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter',
  #         ::Msf::Config.user_script_directory + ::File::SEPARATOR + 'resource' + ::File::SEPARATOR + 'meterpreter',
  #         '.'
  #       ].each do |dir|
  #         next if not ::File.exist? dir
  #         tabs += ::Dir.new(dir).find_all { |e|
  #           path = dir + ::File::SEPARATOR + e
  #           ::File.file?(path) and ::File.readable?(path)
  #         }
  #       end
  #     rescue Exception
  #     end
  #   else
  #     tabs += tab_complete_filenames(str,words)
  #   end
  #   return tabs
  # end

  # def cmd_enable_unicode_encoding
  #   client.encode_unicode = true
  #   print_status('Unicode encoding is enabled')
  # end
  #
  # def cmd_disable_unicode_encoding
  #   client.encode_unicode = false
  #   print_status('Unicode encoding is disabled')
  # end

  # @@client_extension_search_paths = [::File.join(Rex::Root, 'post', 'meterpreter', 'ui', 'console', 'command_dispatcher')]
  #
  # def self.add_client_extension_search_path(path)
  #   @@client_extension_search_paths << path unless @@client_extension_search_paths.include?(path)
  # end
  #
  # def self.client_extension_search_paths
  #   @@client_extension_search_paths
  # end

  def unknown_command(cmd, line)
    status = super

    # if status.nil?
    #   # Check to see if we can find this command in another extension. This relies on the core extension being the last
    #   # in the dispatcher stack which it should be since it's the first loaded.
    #   Rex::Post::Meterpreter::ExtensionMapper.get_extension_names.each do |ext_name|
    #     next if extensions.include?(ext_name)
    #     ext_klass = get_extension_client_class(ext_name)
    #     next if ext_klass.nil?
    #
    #     if ext_klass.has_command?(cmd)
    #       print_error("The \"#{cmd}\" command requires the \"#{ext_name}\" extension to be loaded (run: `load #{ext_name}`)")
    #       return :handled
    #     end
    #   end
    # end

    status
  end

protected

  # attr_accessor :extensions # :nodoc:
  # attr_accessor :bgjobs, :bgjob_id # :nodoc:

  # CommDispatcher = Console::CommandDispatcher

  #
  # Loads the client extension specified in mod
  #
  # def add_extension_client(mod)
  #   klass = get_extension_client_class(mod)
  #
  #   if klass.nil?
  #     print_error("Failed to load client portion of #{mod}.")
  #     return false
  #   end
  #
  #   # Enstack the dispatcher
  #   self.shell.enstack_dispatcher(klass)
  #
  #   # Insert the module into the list of extensions
  #   self.extensions << mod
  # end

  # def get_extension_client_class(mod)
  #   self.class.client_extension_search_paths.each do |path|
  #     path = ::File.join(path, "#{mod}.rb")
  #     klass = CommDispatcher.check_hash(path)
  #     return klass unless klass.nil?
  #
  #     old = CommDispatcher.constants
  #     next unless ::File.exist? path
  #
  #     return nil unless require(path)
  #
  #     new  = CommDispatcher.constants
  #     diff = new - old
  #
  #     next if (diff.empty?)
  #
  #     klass = CommDispatcher.const_get(diff[0])
  #
  #     CommDispatcher.set_hash(path, klass)
  #     return klass
  #   end
  # end

  # def tab_complete_modules(str, words)
  #   tabs = []
  #   client.framework.modules.post.map do |name,klass|
  #     tabs << 'post/' + name
  #   end
  #   client.framework.modules.module_names('exploit').
  #     grep(/(multi|#{Regexp.escape(client.platform)})\/local\//).each do |name|
  #     tabs << 'exploit/' + name
  #   end
  #   return tabs.sort
  # end

end

end
end
end
end
