##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Mock error auxiliary module',
        'Description' => 'Mock error auxiliary module',
        'Author' => 'Unknown',
        'License' => MSF_LICENSE,
        'References' => [
        ]
      )
    )

    register_options([
      Opt::RPORT(1337)
    ])
  end

  def run
    print_status("Mock error auxiliary module for #{datastore['RHOST']}")
    raise "mock error for #{datastore['RHOST']}"
  end
end
