##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/smb'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  def initialize
    super(
      'Name'           => 'everything required',
      'Description'    => %q{
        testing when everything is required
      },
      'Author'         =>
        [
          'test module'
        ],
      'References'     =>
        [
        ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'DB_ALL_CREDS'    => false,
          'BLANK_PASSWORDS' => false,
          'USER_AS_PASS'    => false
        }
    )

    # These are normally advanced options, but for this module they have a
    # more active role, so make them regular options.
    register_options(
      [
        OptBool.new('RHOSTS', [ true, "This is my description", false ]),
      ])

    deregister_options('USERNAME','PASSWORD', 'PASSWORD_SPRAY')
  end

  def run
    print_status "Running #{self.datastore}"
  end
end
