lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

# load 'test/lib/module_test.rb'
# load 'lib/rex/text.rb'
# load 'lib/msf/core/post/linux/system.rb'
# load 'lib/msf/core/post/unix/enum_user_dirs.rb'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::Post::Linux::System
  include Msf::Post::Unix
  include Msf::Post::Common

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Testing Remote Unix System Manipulation',
        'Description' => %q{ This module will test Post::File API methods },
        'License' => MSF_LICENSE,
        'Author' => [ 'egypt'],
        'Platform' => [ 'linux', 'unix', 'java', 'osx' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
    )
  end

  def test_unix
    it "should list users" do
      ret = true
      users = get_users
      vprint_status("get_users result: #{get_users.inspect}")
      ret &&= users.kind_of? Array
      vprint_status("is an array? #{users.length > 0}")
      ret &&= users.length > 0
      have_root = false
      vprint_status("before ret")
      if ret
        vprint_status("before users each")
        users.each { |u|
          vprint_status("before checking root")
          vprint_status("before checking, we expect: #{"root".bytes} #{"root".encoding}")
          vprint_status("before checking, they give expect: #{u[:name].bytes} #{u[:name].encoding}")

          next unless u[:name] == "root"

          vprint_status("we succeeded looking for root: #{u[:name] == "root"}")

          have_root = true
        }
      end
      ret
      ret &&= have_root

      ret
    end
  end

end
