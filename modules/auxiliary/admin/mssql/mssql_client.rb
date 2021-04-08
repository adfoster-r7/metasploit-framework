##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::AggregateModule

  def initialize
    super(
      'Name' => 'Microsoft SQL Server Client',
      'Description' => %q{
        A typical work flow consists of loading the module, setting your options,
        and using the required action commands.

        Example:

          use auxiliary/scanner/mysql/mysql_client

          set RHOSTS 127.0.0.1
          set USERNAME username
          set PASSWORD password

          version
          login
          dump_all

        Options are case-insensitive can also be inlined for ease of use:

          version rhosts=127.0.0.1
          login rhosts=127.0.0.1 username=root pass_filE=./wordlist.txt verbose=true
          exec username=root password=password sql='select version()'

        View the currently available options with:

          options version
          options login
          options dump_all
      },
      'Author' => ['Metasploit people'],
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
      ]
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
        # TODO: Decide on naming conventions across modules, i.e. `dump_all` or similar instead of `gather` ?
        'dump_all',
        {
          'Description' => 'all the enumeration',
          'InvokesTags' => [:gather]
        }
      ],
      [
        'enumdump',
        {
          'Description' => 'Enumerate mysql',
          'ModuleName' => 'auxiliary/admin/mysql/mysql_enum',
          'AssociatedTags' => [:enum]
        },
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
        'userdump',
        {
          'Description' => 'Dump the users',
          'ModuleName' => 'auxiliary/admin/mssql/mssql_enum_sql_logins',
          'AssociatedTags' => [:gather]
        },
      ],
      # [
      #   'userdump',
      #   {
      #     'Description' => 'Dump the hashes',
      #     'ModuleName' => 'auxiliary/admin/mssql/mssql_enum_sql_logins',
      #     'AssociatedTags' => [:gather]
      #   }
      # ]
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
        'exec',
        {
          'Description' => 'Execute mysql commands',
          'ModuleName' => 'auxiliary/admin/mysql/mysql_sql',
          'AssociatedTags' => [],
        }
      ]
    ]
  end
end
