# -*- coding: binary -*-
module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Recon module command dispatcher.
#
###
class Auxiliary

  include Msf::Ui::Console::ModuleCommandDispatcher
  include Msf::Ui::Console::ModuleOptionTabCompletion

  @@auxiliary_action_opts = Rex::Parser::Arguments.new(
    '-h' => [ false, 'Help banner.'                                                        ],
    '-j' => [ false, 'Run in the context of a job.'                                        ],
    '-o' => [ true,  'A comma separated list of options in VAR=VAL format.'                ],
    '-q' => [ false, 'Run the module in quiet mode with no output'                         ]
  )

  @@auxiliary_opts = Rex::Parser::Arguments.new(@@auxiliary_action_opts.fmt.merge(
    '-a' =>  [ true,  'The action to use.  If none is specified, ACTION is used.'],
  ))

  #
  # Returns the hash of commands specific to auxiliary modules.
  #
  def action_commands
      mod.actions.map { |action| [action.name.downcase, action.description] }.to_h
  end

  #
  # Returns the hash of commands specific to auxiliary modules.
  #
  def commands
    super.update({
      "run"      => "Launches the auxiliary module",
      "rcheck"   => "Reloads the module and checks if the target is vulnerable",
      "rerun"    => "Reloads and launches the auxiliary module",
      "exploit"  => "This is an alias for the run command",
      "recheck"  => "This is an alias for the rcheck command",
      "rexploit" => "This is an alias for the rerun command",
      "reload"   => "Reloads the auxiliary module"
    }).merge( (mod ? mod.auxiliary_commands : {}) ).merge(action_commands)
  end

  #
  # Allow modules to define their own commands
  #
  def method_missing(meth, *args)
    if (mod and mod.respond_to?(meth.to_s, true) )

      # Initialize user interaction
      mod.init_ui(driver.input, driver.output)

      return mod.send(meth.to_s, *args)
    end

    # TODO: This existing code is funky
    action_name = meth.to_s.delete_prefix('cmd_')
    if mod && mod.kind_of?(Msf::Module::HasActions) && mod.actions.map(&:name).any? { |a| a.casecmp?(action_name) }
       return do_action(action_name, *args)
    end

    if meth.to_s.end_with?("_tabs")
      # require 'pry'; binding.pry
      action_name = meth.to_s.delete_prefix('cmd_').delete_suffix("_tabs")
      # require 'pry'; binding.pry
      if mod && mod.kind_of?(Msf::Module::HasActions) && mod.actions.map(&:name).any? { |a| a.casecmp?(action_name) }
        return do_action_tabs(action_name, *args)
      end
    end

    return
  end

  #
  #
  # Execute the module with a set action
  #
  def do_action(action_name, *args)
    action = mod.actions.find { |action| action.name.casecmp?(action_name) }
    raise Msf::MissingActionError.new(action_name) if action.nil?

    cmd_run(*args, action: action.name)
  end

  # TODO: This existing code is funky
  def do_action_tabs(action_name, str, words)
    action = mod.actions.find { |action| action.name.casecmp?(action_name) }
    raise Msf::MissingActionError.new(meth) if action.nil?

    # TODO: Confirm that the action is present, and the module has the mixin functionality for being powered by sub modules
    # TODO: The actions command could in theory still be used with flags. This functionality would need to be updated to support flags / contributing the existing `run` command's tab array
    # TOO: Confirm the performance overhead of this
    mod = framework.modules.create(action.module_name)
    tab_complete_option(mod, str, words)
  end

  # TODO: The previous action names as commands code didn't implement respond_to, put in a hack for spiking
  def respond_to?(meth, *args)
    if meth.to_s.end_with?("_tabs")
      action = meth.to_s.delete_prefix('cmd_').delete_suffix("_tabs")
      # require 'pry'; binding.pry
      if action && mod && mod.kind_of?(Msf::Module::HasActions) && mod.actions.map(&:name).any? { |a| a.casecmp?(action) }
        return true
      end
    end

    super(meth, *args)
  end

  #
  #
  # Returns the command dispatcher name.
  #
  def name
    "Auxiliary"
  end

  #
  # Tab completion for the run command
  #
  def cmd_run_tabs(str, words)
    flags = @@auxiliary_opts.fmt.keys
    options = tab_complete_option(active_module, str, words)
    flags + options
  end

  #
  # Executes an auxiliary module
  #
  def cmd_run(*args, action: nil)
    opts    = []
    action  ||= mod.datastore['ACTION']
    jobify  = false
    quiet   = false

    @@auxiliary_opts.parse(args) do |opt, idx, val|
      case opt
      when '-j'
        jobify = true
      when '-o'
        opts.push(val)
      when '-a'
        action = val
      when '-q'
        quiet  = true
      when '-h'
        if action.nil?
          cmd_run_help
        else
          cmd_action_help(action)
        end
        return false
      else
        if val[0] != '-' && val.match?('=')
          opts.push(val)
        else
          cmd_run_help
          return false
        end
      end
    end

    # Always run passive modules in the background
    if mod.is_a?(Msf::Module::HasActions) &&
        (mod.passive || mod.passive_action?(action || mod.default_action))
      jobify = true
    end


    # TODO: This won't work. The auxilary runner supports rhosts functionality. In the case of the smb version module, this command handler sets RHOST = x.x.x.x, but RHOSTS is still set. When the request is proxied through by AggregateModule to the target, it breaks this assumption - as the scanner plucks out 'rhosts' - and starts walking over the range all over again.
    rhosts = datastore['RHOSTS']
    begin
      # Check if this is a scanner module or doesn't target remote hosts
      if rhosts.blank? || mod.class.included_modules.include?(Msf::Auxiliary::Scanner)
        mod.run_simple(
          'Action'         => action,
          'OptionStr'      => opts.join(','),
          'LocalInput'     => driver.input,
          'LocalOutput'    => driver.output,
          'RunAsJob'       => jobify,
          'Quiet'          => quiet
        )
      # For multi target attempts with non-scanner modules.
      else
        rhosts_opt = Msf::OptAddressRange.new('RHOSTS')
        if !rhosts_opt.valid?(rhosts)
          print_error("Auxiliary failed: option RHOSTS failed to validate.")
          return false
        end

        rhosts_range = Rex::Socket::RangeWalker.new(rhosts_opt.normalize(rhosts))
        rhosts_range.each do |rhost|
          require 'pry'; binding.pry
          nmod = mod.replicant
          nmod.datastore['RHOST'] = rhost
          print_status("Running module against #{rhost}")
          nmod.run_simple(
            'Action'         => action,
            'OptionStr'      => opts.join(','),
            'LocalInput'     => driver.input,
            'LocalOutput'    => driver.output,
            'RunAsJob'       => false,
            'Quiet'          => quiet
          )
        end
      end
    rescue ::Timeout::Error
      print_error("Auxiliary triggered a timeout exception")
      print_error("Call stack:")
      e.backtrace.each do |line|
        break if line =~ /lib.msf.base.simple/
        print_error("  #{line}")
      end
    rescue ::Interrupt
      print_error("Auxiliary interrupted by the console user")
    rescue ::Msf::MissingActionError => e
      if active_module.is_a?(Msf::AggregateModule)
        print_error("Run command not supported, please use one of the following action names instead:")
        self.driver.run_single("actions")
      else
        print_error("Action not specified. Either specify it with 'set ACTION action_name' and run again, or simply use the action name as the command")
        self.driver.run_single("actions")
      end
      return false
    rescue ::Exception => e
      print_error("Auxiliary failed: #{e.class} #{e}")
      # require 'pry'; binding.pry
      if(e.class.to_s != 'Msf::OptionValidateError')
        print_error("Call stack:")
        e.backtrace.each do |line|
          # break if line =~ /lib.msf.base.simple/
          print_error("  #{line}")
        end
      end

      return false
    end

    if (jobify && mod.job_id)
      print_status("Auxiliary module running as background job #{mod.job_id}.")
    else
      print_status("Auxiliary module execution completed")
    end
  end

  alias cmd_exploit cmd_run
  alias cmd_exploit_tabs cmd_run_tabs

  def cmd_run_help
    print_line "Usage: run [options]"
    print_line
    print_line "Launches an auxiliary module."
    print @@auxiliary_opts.usage
  end

  def cmd_action_help(action)
    print_line "Usage: " + action.downcase + " [options]"
    print_line
    print_line "Launches an auxiliary module."
    print @@auxiliary_action_opts.usage
  end

  alias cmd_exploit_help cmd_run_help

  #
  # Reloads an auxiliary module and executes it
  #
  def cmd_rerun(*args)
    if reload(true)
      cmd_run(*args)
    end
  end

  alias cmd_rerun_tabs cmd_run_tabs
  alias cmd_rexploit cmd_rerun
  alias cmd_rexploit_tabs cmd_exploit_tabs

  #
  # Reloads an auxiliary module and checks the target to see if it's
  # vulnerable.
  #
  def cmd_rcheck(*args)
    reload()

    cmd_check(*args)
  end

  alias cmd_recheck cmd_rcheck

end

end end end end

