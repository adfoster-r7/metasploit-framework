##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::AggregateModule

  def initialize
    super(
      'Name' => 'MySQL Client module',
      'Description' => 'Combines all of the utilities required for MySQL enumeration/exploitation',
      'Author' => 'Metasploit people',
      'License' => MSF_LICENSE,
      'Actions' => (
      enum +
        checks +
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
          'Description' => 'Get the mysql version',
          'ModuleName' => 'auxiliary/scanner/mysql/mysql_version',
          'AssociatedTags' => %i[check enum]
        }
      ],
      [
        'shares',
        {
          'Description' => 'Enumerate mysql',
          'ModuleName' => 'admin/mysql/mysql_enum',
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
      ]
    ]
  end

  def gather
    [
      [
        # TODO: `dump_all` or similar instead of `gather` ?
        'gather_all',
        {
          'Description' => 'all the enumeration',
          'InvokesTags' => [:gather]
        }
      ],
      [
        'schemadump',
        {
          'Description' => 'Dump the schema',
          'ModuleName' => 'auxiliary/scanner/mysql/mysql_schemadump',
          'AssociatedTags' => [:gather]
        },
      ],
      [
        'hashdump',
        {
          'Description' => 'Dump the secrets',
          'ModuleName' => 'auxiliary/scanner/mysql/mysql_hashdump',
          'AssociatedTags' => [:gather]
        },
      ]
    ]
  end

  def misc
    [
      [
        'login',
        {
          'Description' => 'Attempt to log in',
          'ModuleName' => 'auxiliary/scanner/mysql/mysql_login',
          'AssociatedTags' => []
        }
      ],
      [
        'command',
        {
          'Description' => 'Execute mysql commands',
          'ModuleName' => 'auxiliary/admin/mysql/mysql_sql',
          'AssociatedTags' => []
        }
      ],
    ]
  end
end
