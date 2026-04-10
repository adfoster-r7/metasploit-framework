require 'rex'

lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Testing FTP sessions work',
        'Description' => %q{ This module will test the FTP sessions work },
        'License' => MSF_LICENSE,
        'Author' => ['unknown'],
        'Platform' => all_platforms,
        'SessionTypes' => ['ftp']
      )
    )
  end

  def test_console_help
    it 'should support the help command' do
      stdout = with_mocked_console(session) { |console| console.run_single('help') }
      ret = true
      ret &&= stdout.buf.include?('Core Commands')
      ret &&= stdout.buf.include?('FTP Client Commands')
      ret
    end
  end

  def test_console_pwd
    it 'should return a valid directory path' do
      stdout = with_mocked_console(session) { |console| console.run_single('pwd') }
      ret = true
      ret &&= stdout.buf.match?(%r{/})
      ret
    end
  end

  def test_console_ls
    it 'should return directory listing output' do
      stdout = with_mocked_console(session) { |console| console.run_single('ls') }
      ret = true
      # ls should produce some output (even if empty directory, the command should not error)
      ret &&= !stdout.buf.include?('Failed to list directory')
      ret
    end
  end

  private

  def all_platforms
    Msf::Module::Platform.subclasses.collect { |c| c.realname.downcase }
  end

  # Wrap the console with a mocked stdin/stdout for testing purposes.
  # @param [Session] session
  # @return [Rex::Ui::Text::Output::Buffer] the stdout buffer
  def with_mocked_console(session)
    old_input = session.console.input
    old_output = session.console.output

    mock_input = Rex::Ui::Text::Input.new
    mock_output = Rex::Ui::Text::Output::Buffer.new

    session.console.init_ui(mock_input, mock_output)
    yield session.console

    mock_output
  ensure
    session.console.init_ui(old_input, old_output)
  end
end
