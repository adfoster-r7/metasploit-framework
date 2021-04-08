##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::AggregateModule

  def initialize
    super(
      'Name' => 'SMB Client module',
      'Description' => %q{
        A typical work flow consists of loading the module, setting your options,
        and using the required action commands.

        Example:

          use auxiliary/scanner/smb/smb_client

          set RHOSTS 127.0.0.1
          set SMBUser username
          set SMBPass password

          enum
          version
          check
          gather_all

        Options are case-insensitive can also be inlined for ease of use:

          version rhosts=127.0.0.1
          login rhosts=127.0.0.1 smbuser=Administrator smbpass='P4$$w0rd' verbose=true
          upload rhosts=127.0.0.1 smbuser=Administrator smbpass='P4$$w0rd' smbshare=shared_folder lpath=./payload.exe rpath=payload.exe
          ls smbshare=shared_folder rpath='foo\bar'

        View the currently available options with:

          options
          options version
          options login
          options check
      },
      'Author' => ['Metasploit people'],
      'License' => MSF_LICENSE,
      'Actions' => (
        enum +
          checks +
          file_handling +
          gather +
          misc
      )
    )
  end

  private

  def enum
    [
      [
        'enum',
        {
          'Description' => 'all the enumeration',
          'InvokesTags' => [:enum]
        }
      ],
      [
        # TODO: Can't use 'version', as it conflicts with the global version command which takes precedent
        'version',
        {
          'Description' => 'Get the smb version',
          'ModuleName' => 'auxiliary/scanner/smb/smb_version',
          'AssociatedTags' => %i[check enum]
        }
      ],
      [
        'shares',
        {
          'Description' => 'Get the smb shares',
          'ModuleName' => 'auxiliary/scanner/smb/smb_enumshares',
          'AssociatedTags' => [:enum]
        },
      ],
      [
        'users',
        {
          'Description' => 'Get the smb users',
          'ModuleName' => 'auxiliary/scanner/smb/smb_enumusers',
          'AssociatedTags' => [:enum]
        },
      ],
      # TODO: Is this used frequently?
      [
        'enum_gpp',
        {
          'Description' => 'Attempt to log in',
          'ModuleName' => 'auxiliary/scanner/smb/smb_enum_gpp',
          'AssociatedTags' => [:enum]
        },
      ],
    ]
  end

  def checks
    [
      [
        # TODO: Decide if we want 'check' to be an action. It means there's no special case handling for logic such as `options check`, `show actions`, but it's also maybe unexpected to module developers.
        'check',
        {
          'Description' => 'Run all module checks associated with this module',
          'InvokesTags' => [:check]
        }
      ],
      [
        'ms17_010',
        # TODO: Confirm if this check handles also handles the coverage of "exploit/windows/smb/ms17_010_eternalblue_win8"
        {
          'Description' => 'Test for ms17_010',
          'ModuleName' => 'auxiliary/scanner/smb/smb_ms17_010',
          'AssociatedTags' => [:check]
        }
      ],
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
      [
        'upload',
        {
          'Description' => 'Upload an arbitrary file',
          'ModuleName' => 'auxiliary/admin/smb/upload_file',
          # 'ExampleUsage' => 'upload lpath=Gemfile.lock rpath=testing smbshare=C$'
          'AssociatedTags' => []
        }
      ],
      [
        'download',
        {
          'Description' => 'download an arbitrary file',
          'ModuleName' => 'auxiliary/admin/smb/download_file',
          'AssociatedTags' => []
        }
      ],
      [
        'ls',
        {
          'Description' => 'list a share directory',
          'ModuleName' => 'auxiliary/admin/smb/list_directory',
          'AssociatedTags' => []
        }
      ],
    ]
  end

  def gather
    [
      [
        'gather_all',
        {
          'Description' => 'all the enumeration',
          'InvokesTags' => [:gather]
        }
      ],
      [
        # TODO: Would secrets dump be under enum?
        'secrets_dump',
        {
          'Description' => 'Dump the secrets',
          'ModuleName' => 'auxiliary/gather/windows_secrets_dump',
          'AssociatedTags' => [:gather]
        },
      ]
    ]
  end

  def misc
    [
      [
        'test_edgecases',
        {
          'Description' => 'Test edge cases',
          'ModuleName' => 'auxiliary/scanner/smb/test_edgecases',
          'AssociatedTags' => []
        }
      ],
      [
        'login',
        {
          'Description' => 'Attempt to log in',
          'ModuleName' => 'auxiliary/scanner/smb/smb_login',
          'AssociatedTags' => []
        }
      ],
      [
        'capture',
        {
          'Description' => 'Run SMB capture server',
          'ModuleName' => 'auxiliary/server/capture/smb',
          'ModuleAction' => 'Capture',
          'AssociatedTags' => []
        }
      ],

    ]
  end
end
