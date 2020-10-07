##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# TODO:
#   - Promote 'actions' to a top level keyboard, as a shortcut to 'show actions'
#   - How would this impact the RPC client?
#   - Running a module without an action currently gives no stack trace:
#       msf6 auxiliary(scanner/smb/client) > run
#       [-] Auxiliary failed: Msf::MissingActionError Invalid action: Please use: Download
#       [-] Call stack:
#       msf6 auxiliary(scanner/smb/client) >
# - 'show options' would need to be updated to support _all_ options from the modules, not just the 'parent'
# - Current implementation assumes that the 'client' module becomes completely empty
#   and delegates all responsibility to other modules.
#
#  This allows existing modules in isolation, useful for Pro + module counts etc,
#  as well as enforing 'single responsibility' still.
#
#  However it might be cumbersome from a developers perspective.

##
# Thi mixin signifies that the module itself implements no functionality.
# Instead it acts as an aggregate module that simply delegates all responsibility
# to other modules
##
module Msf::Module::HasModuleActions
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

    print_status("Using #{module_name} as check")

    # Retrieve the module's return value
    res = mod.run_simple(
      'LocalInput'  => user_input,
      'LocalOutput' => user_output,
      'Options'     => datastore # XXX: This clobbers the datastore!
    )

    res

    # # Ensure return value is a CheckCode
    # case res
    # when Exploit::CheckCode
    #   # Return the CheckCode
    #   res
    # when Hash
    #   # XXX: Find CheckCode associated with RHOST, which is set automatically
    #   checkcode = res[datastore['RHOST']]
    #
    #   # Bail if module doesn't return a CheckCode
    #   unless checkcode.kind_of?(Exploit::CheckCode)
    #     return Exploit::CheckCode::Unsupported(
    #       "#{check_module} does not return a CheckCode."
    #     )
    #   end
    #
    #   # Return the CheckCode
    #   checkcode
    # else
    #   # Bail if module doesn't return a CheckCode
    #   Exploit::CheckCode::Unsupported(
    #     "#{check_module} does not return a CheckCode."
    #   )
    # end
  end
end

class MetasploitModule < Msf::Auxiliary
  include Msf::Module::HasModuleActions

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
          [
            # With the above 'version' namespacing issue, looks like `smb_` prefixes should be followed for now.
            'smb_shares',
            'Description' => 'Get the smb version',
            'ModuleName' => 'auxiliary/scanner/smb/smb_enumshares'
          ]
        ],
    )
  end
end
