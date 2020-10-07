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

##
# This mixin signifies that the module itself implements no functionality.
# Instead it acts as an aggregate module that simply delegates all responsibility
# to other modules
##
module Msf::Module::AggregateModule

  def initialize(info)
    super

    # TODO: Not sure about the UX for the user here.
    # Register _all_ children actions in the aggregate module.
    actions.each do |action|
      mod = framework.modules.create(action.module_name)
      # TODO: Investigate the current semantics. Particularly: validating duplicate names / difference types etc, as well as different default values - particularly for randomized fields
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

  def run
    module_name = action.module_name
    mod = framework.modules.create(module_name)

    # Bail if it isn't aux
    if mod.type != Msf::MODULE_AUX
      return Exploit::CheckCode::Unsupported(
        "#{check_module} is not an auxiliary module."
      )
    end

    # Bail if run isn't defined
    unless mod.respond_to?(:run)
      return Exploit::CheckCode::Unsupported(
        "#{check_module} does not define a run method."
      )
    end

    print_status("Using #{module_name} as action")

    # Retrieve the module's return value
    res = mod.run_simple(
      'LocalInput'  => user_input,
      'LocalOutput' => user_output,
      'Options'     => datastore # XXX: This clobbers the datastore!
    )

    res
  end
end

class MetasploitModule < Msf::Auxiliary
  include Msf::Module::AggregateModule

  def initialize
    super(
      'Name' => 'SMB Client module',
      'Description' => 'Combines all of the utilities required for SMB enumeration/exploitation',
      'Author' => 'Metasploit people',
      'License' => MSF_LICENSE,
      'Actions' =>
        [
          [
            # Note: Can't use 'version', as it conflicts with the global version command which takes precedent
            'smb_version',
            'Description' => 'Get the smb version',
            'ModuleName' => 'auxiliary/scanner/smb/smb_version'
          ],
          # TODO: Would we want to add a "enumerate everything" action?
          # [
          #   'smb_enumall',
          #   'Description' => 'all the enumeration',
          #   'ModuleNames' => ['auxiliary/scanner/smb/smb_enumshares', ... ] ?
          # ],
          [
            # With the above 'version' namespacing issue, looks like `smb_` prefixes should be followed for now.
            'smb_enumshares',
            'Description' => 'Get the smb shares',
            'ModuleName' => 'auxiliary/scanner/smb/smb_enumshares'
          ],
          [
            # With the above 'version' namespacing issue, looks like `smb_` prefixes should be followed for now.
            'smb_enumusers',
            'Description' => 'Get the smb users',
            'ModuleName' => 'auxiliary/scanner/smb/smb_enumusers'
          ],
          [
            'smb_enumgpp',
            'Description' => 'Attempt to log in',
            'ModuleName' => 'auxiliary/scanner/smb/smb_enum_gpp'
          ],
          [
            # On the fence about this being here
            'smb_secretsdump',
            'Description' => 'Dump the secrets',
            'ModuleName' => 'auxiliary/gather/windows_secrets_dump'
          ],
          [
            'smb_login',
            'Description' => 'Attempt to log in',
            'ModuleName' => 'auxiliary/scanner/smb/smb_login'
          ],
        ],
    )
  end
end
