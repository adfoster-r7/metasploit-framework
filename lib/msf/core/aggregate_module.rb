##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# TODO:
#   - Promote 'actions' to a top level keyboard, as a shortcut to 'show actions'
#     msf6 auxiliary(scanner/smb/client) > actions
#       [-] Unknown command: actions.
#   - Will we need to consider any RPC client changes?
#   - XXX: Running a module without an action currently gives no stack trace:
#       msf6 auxiliary(scanner/smb/client) > run
#       [-] Auxiliary failed: Msf::MissingActionError Invalid action: Please use: Download
#       [-] Call stack:
#       msf6 auxiliary(scanner/smb/client) >
#   - 'show options' would need to be updated to support _all_ options from the modules, not just the 'parent'
#  - Current implementation assumes that the 'client' module becomes completely empty
#     and delegates all responsibility to other modules.
#
#     This allows existing modules in isolation, useful for Pro + module counts etc,
#     as well as enforing 'single responsibility' still.
#
#     However it might be cumbersome from a developers perspective.
#   - We'll have to update the 'reload' command to reload module dependencies
#   - TODO: Where would 'clients', or 'collection of module' modules live? Auxilliary? A new folder?
#     iirc Auxiliary modules shouldn't gain shells, but this module should be capable of gaining sessions IMO
#   - TODO: Align the functionality of 'options' and 'show options'
#   - TODO: Should 'aggregate' module options on the parent, and should they be validating their children's options?
#   - TODO: Do we need to add support for 'options action_name' ?
#   - Should we support the functionality of 'set ACTION foo' and 'run' still?
#   - Should we enforce that no sub modules have actions set?
#     i.e. An aggregate module can't depend on a module that itself has additional options
#   - TODO: We would most likely have to update the 'info' command, including `info -d`
#   - TODO: Will this break any downstream automation / assumptions if an 'aggregate module' is implemented as a mixin
#   - TODO: The upload/download modules for smb aren't great / consistent with expectations, i.e. expecting `download` download to the current working directory

##
# This mixin signifies that the module itself implements no functionality.
# Instead it acts as an aggregate module that simply delegates all responsibility
# to other modules
##
module Msf::AggregateModule

  def initialize(info)
    super

    # TODO: This validation should most likely be implemented elsewhere
    duplicate_action_names = actions.group_by(&:name).select { |_name, values| values.length > 1 }
    if duplicate_action_names.any?
      raise "Found duplicate action names: #{duplicate_action_names.keys.join(', ')}"
    end

    # TODO: Not sure about the UX for the user here.
    # Register _all_ children actions in the aggregate module.
    actions.each do |action|
      unless action.module_name || action.invokes_tags
        raise "Action '#{action.name}' should have an associated module, or be invoke other tags"
      end

      next unless action.module_name
      mod = framework.modules.create(action.module_name)
      unless mod.auxiliary?
        raise "Action '#{action.name}' is wanting to run a module that isn't an auxiliary module #{action.module_name}', this functionality is not supported"
      end

      # TODO: Investigate the current semantics of merging multiple properties. Particularly: validating duplicate names / difference types etc, as well as different default values - particularly for randomized fields
      mod.options.values.each do |option|
        if option.advanced?
          register_advanced_options([option])
        elsif option.evasion?
          register_evasion_options([option])
        else
          register_options([option])
        end
      end
    end
  end

  def check
    check_action = actions.find { |action| action.name.casecmp?('check') }
    unless check_action
      raise ::NoMethodError.new(Msf::Exploit::CheckCode::Unsupported.message, 'check')
    end

    run_action(check_action)
  end

  def run
    run_action(action)
  end

  def find_modules_by_action(action)
    if action.invokes_tags
      find_modules_by_tags(action.invokes_tags)
    else
      [action.module_name]
    end
  end

  def find_modules_by_tags(required_tags)
    associate_actions = actions.select do |candidate_action|
      (candidate_action.associated_tags & required_tags).any?
    end

    associate_actions.map(&:module_name)
  end

  private

  def run_action(action)
    associated_modules = find_modules_by_action(action)
    associated_modules.each do |module_name|
      run_module(module_name)
    rescue => e
      $stderr.puts "TODO: Error handling. Module failed #{e}"
    end
  end

  def run_module(module_name)
    mod = framework.modules.create(module_name)

    # Bail if it isn't aux
    if mod.type != Msf::MODULE_AUX
      return Exploit::CheckCode::Unsupported(
        "#{mod} is not an auxiliary module."
      )
    end

    # Bail if run isn't defined
    unless mod.respond_to?(:run)
      return Exploit::CheckCode::Unsupported(
        "#{mod} does not define a run method."
      )
    end

    print_status("---------------------- Using #{module_name} as action ----------------------")

    # Retrieve the module's return value
    res = mod.run_simple(
      'LocalInput' => user_input,
      'LocalOutput' => user_output,
      'Options' => datastore # XXX: This clobbers the datastore!
    )

    print("\n\n")

    res
  end
end
