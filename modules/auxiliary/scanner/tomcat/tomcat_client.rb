##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::AggregateModule

  def initialize
    super(
      'Name' => 'Tomcat workspace',
      'Description' => %q{
        # A typical work flow consists of loading the module, setting your options,
        # and using the required action commands.
        #
        # Example:
        #
        #   use auxiliary/scanner/mysql/mysql_client
        #
        #   set RHOSTS 127.0.0.1
        #   set USERNAME username
        #   set PASSWORD password
        #
        #   version
        #   login
        #   dump_all
        #
        # Options are case-insensitive can also be inlined for ease of use:
        #
        #   version rhosts=127.0.0.1
        #   login rhosts=127.0.0.1 username=root pass_file=./wordlist.txt verbose=true
        #   exec username=root password=password sql='select version()'
        #
        # View the currently available options with:
        #
        #   options version
        #   options login
        #   options dump_all
      },
      'Author' => 'Metasploit people',
      'License' => MSF_LICENSE,
      'Actions' => (
      enum +
        checks +
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
        'enumusers',
        {
          'Description' => 'Enumerate users',
          'ModuleName' => 'auxiliary/scanner/http/tomcat_enum',
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

  def misc
    [
      [
        'login',
        {
          'Description' => 'Attempt to log in',
          'ModuleName' => 'auxiliary/scanner/http/tomcat_mgr_login',
          'AssociatedTags' => []
        }
      ],
      [
        'ghostcat',
        {
          'Description' => 'Execute mysql commands',
          'ModuleName' => 'auxiliary/admin/http/tomcat_ghostcat',
          'AssociatedTags' => [:check]
        }
      ]
    ]
  end
end
