##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::AggregateModule

  def initialize
    super(
      'Name' => 'SMB Client module',
      'Description' => 'Combines all of the utilities required for SMB enumeration/exploitation',
      'Author' => ['Metasploit people'],
      'License' => MSF_LICENSE,
      'Actions' => enum + checks + file_handling + gather + misc
    )
  end

  private

  def enum
    [
      [
        'enum',
        'Description' => 'all the enumeration',
        'InvokesTags' => [:enum]
      ],
      [
        # TODO: Can't use 'version', as it conflicts with the global version command which takes precedent
        'version',
        'Description' => 'Get the ssh version',
        'ModuleName' => 'auxiliary/scanner/ssh/ssh_version',
        'AssociatedTags' => [:check, :enum]
      ],
      # [
      #   'shares',
      #   'Description' => 'Get the smb shares',
      #   'ModuleName' => 'auxiliary/scanner/smb/smb_enumshares',
      #   'AssociatedTags' => [:enum],
      # ],
      # [
      #   'users',
      #   'Description' => 'Get the smb users',
      #   'ModuleName' => 'auxiliary/scanner/ssh/ssh_enumusers',
      #   'AssociatedTags' => [:enum],
      # ],
      # # TODO: Is this used frequently?
      # [
      #   'enum_gpp',
      #   'Description' => 'Attempt to log in',
      #   'ModuleName' => 'auxiliary/scanner/smb/smb_enum_gpp',
      #   'AssociatedTags' => [:enum],
      # ],
    ]
  end

  def checks
    [
      # [
      #   # TODO: Decide if we want 'check' to be an action. It means there's no special case handling for logic such as `options check`, `show actions`, but it's also maybe unexpected to module developers.
      #   'check',
      #   'Description' => 'Run all module checks associated with this module',
      #   'InvokesTags' => [:check]
      # ],
      # [
      #   'ms17_010',
      #   # TODO: Confirm if this check handles also handles the coverage of "exploit/windows/smb/ms17_010_eternalblue_win8"
      #   'Description' => 'Test for ms17_010',
      #   'ModuleName' => 'auxiliary/scanner/smb/smb_ms17_010',
      #   'AssociatedTags' => [:check]
      # ],
    # [
    #   'ms08_067_netapi',
    #   'Description' => 'Test for ms08_067_netapi',
    #   # TODO: Discuss whether we want exploits to be allowed. It should most likely only allow check methods.
    #   'ModuleName' => 'windows/smb/ms08_067_netapi',
    #   'AssociatedTags' => [:check]
    # ]
    ]
  end

  # TODO: This may be awkward using, the user might expect 'upload foo', similar to evil-winrm and meterpreter's API.
  def file_handling
    [
      # [
      #   'upload',
      #   'Description' => 'Upload an arbitrary file',
      #   'ModuleName' => 'auxiliary/admin/smb/upload_file',
      #   # 'ExampleUsage' => 'upload lpath=Gemfile.lock rpath=testing smbshare=C$'
      #   'AssociatedTags' => []
      # ],
      # [
      #   'download',
      #   'Description' => 'download an arbitrary file',
      #   'ModuleName' => 'auxiliary/admin/smb/download_file',
      #   'AssociatedTags' => []
      # ],
    # TODO: `ls` functionality
    ]
  end

  def gather
    [
      # [
      #   'gather_all',
      #   'Description' => 'all the enumeration',
      #   'InvokesTags' => [:gather]
      # ],
      # [
      #   # TODO: Would secrets dump be under enum?
      #   'secrets_dump',
      #   'Description' => 'Dump the secrets',
      #   'ModuleName' => 'auxiliary/gather/windows_secrets_dump',
      #   'AssociatedTags' => [:gather],
      # ]
    ]
  end

  def misc
    [
      # TODO: Login for smb and ssh have different properties for 'username', 'smbuser'
      [
        'login',
        'Description' => 'Attempt to log in',
        'ModuleName' => 'auxiliary/scanner/ssh/ssh_login',
        'AssociatedTags' => []
      ],
    ]
  end
end
