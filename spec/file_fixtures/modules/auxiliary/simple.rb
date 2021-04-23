##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Boilerplate auxiliary scanner',
        'Description' => 'Test!',
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
    print_status("Mock scanner for #{datastore['RHOST']}")
    "simple result for #{datastore['RHOST']}"
  end
end
