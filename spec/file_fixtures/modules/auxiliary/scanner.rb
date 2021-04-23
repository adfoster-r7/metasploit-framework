##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Mock scanner auxiliary module',
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

  def run_host(ip)
    print_status("Mock scanner auxiliary scanner for #{ip}")
    "scanner result for #{ip}"
  end
end
