

require 'spec_helper'
require 'msf/ui/debug'
require 'msf/base/config'

RSpec.describe 'Debug command functionality' do

  FILE_FIXTURES_PATH = File.join(Msf::Config.install_root, 'spec', 'file_fixtures')

  describe Msf::Ui::Debug do
    before(:each) do
    end

    it "correctly parses an error log" do
      allow(::Msf::Config).to receive(:log_directory).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'error_logs', 'basic'))

      error_log_output = <<~LOG
        ##  %grnErrors%clr
        The following errors occurred before the issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        [00/00/0000 00:00:00] [e(0)] error: [-] Error 1

        [11/11/1111 11:11:11] [e(0)] error: [-] Error 2
        Call stack:
        Stack_Trace
        stack trace
        STACK-TRACE

        [22/22/2222 22:22:22] [e(0)] error: [-] Error 3
        ```

        </details>


      LOG

      expect(subject.errors).to eql(error_log_output)
    end

    it "correctly parses an error log file larger than the log line total" do
      allow(::Msf::Config).to receive(:log_directory).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'error_logs', 'long'))

      logs = ''

      digits = 11..20

      digits.each do |d|
        logs += "[00/00/0000 00:00:00] [e(0)] error: [-] Error #{d}\n\n"
      end

      error_log_output = <<~LOG
        ##  %grnErrors%clr
        The following errors occurred before the issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        #{logs.strip}
        ```

        </details>


      LOG

      expect(subject.errors).to eql(error_log_output)
    end

    it "correctly parses an empty error log file" do
      allow(::Msf::Config).to receive(:log_directory).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'error_logs', 'empty'))

      error_log_output = <<~EMPTY
        ##  %grnErrors%clr
        The following errors occurred before the issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        The error log file was empty
        ```

        </details>


      EMPTY

      expect(subject.errors).to eql(error_log_output)
    end

    it "correctly retrieves & parses a command history shorter than the command total" do
      Readline::HISTORY = Array.new(4) { |i| "Command #{i+1}"}

      error_log_output = <<~E_LOG
        ##  %grnHistory%clr
        The following commands were ran before this issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        0      Command 1
        1      Command 2
        2      Command 3
        3      Command 4
        ```

        </details>


      E_LOG

      expect(subject.history).to eql(error_log_output)
    end

    it "correctly retrieves & parses a command history equal in length to the command total" do
      Readline::HISTORY = Array.new(10) { |i| "Command #{i+1}"}
      error_log_output = <<~E_LOG
        ##  %grnHistory%clr
        The following commands were ran before this issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        0      Command 1
        1      Command 2
        2      Command 3
        3      Command 4
        4      Command 5
        5      Command 6
        6      Command 7
        7      Command 8
        8      Command 9
        9      Command 10
        ```

        </details>


      E_LOG

      expect(subject.history).to eql(error_log_output)
    end

    it "correctly retrieves & parses a command history larger than the command total" do
      Readline::HISTORY = Array.new(15) { |i| "Command #{i+1}"}
      error_log_output = <<~E_LOG
        ##  %grnHistory%clr
        The following commands were ran before this issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        0      Command 1
        1      Command 2
        2      Command 3
        3      Command 4
        4      Command 5
        5      Command 6
        6      Command 7
        7      Command 8
        8      Command 9
        9      Command 10
        10     Command 11
        11     Command 12
        12     Command 13
        13     Command 14
        14     Command 15
        ```

        </details>


      E_LOG

      expect(subject.history).to eql(error_log_output)
    end

    it "correctly retrieves & parses an empty config file & datastore" do
      allow(::Msf::Config).to receive(:config_file).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'config_files', 'empty.ini'))

      framework = double('framework')
      expect(framework).to receive(:datastore).and_return({})


      driver = double('driver')
      expect(driver).to receive(:get_config_core).and_return('config_core')
      expect(driver).to receive(:get_config).and_return({})
      expect(driver).to receive(:get_config_group).and_return('config_group')
      expect(driver).to receive(:active_module).and_return(nil)

      expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr
      The following global/module datastore, & databse setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      The local config file is empty, no global variables are set, and there is no active module.
      ```

      </details>


      OUTPUT

      expect(subject.datastore(framework, driver)).to eql(expected_output)
    end

    it "correctly retrieves & parses a populated global datastore" do
      allow(::Msf::Config).to receive(:config_file).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'config_files', 'empty.ini'))

      framework = double('framework')
      expect(framework).to receive(:datastore).and_return({
                                                            'key1' => 'val1',
                                                            'key2' => 'val2',
                                                            'key3' => 'val3'
                                                           })


      driver = double('driver')
      expect(driver).to receive(:get_config_core).and_return('group/name/1')
      expect(driver).to receive(:get_config).and_return({})
      expect(driver).to receive(:get_config_group).and_return('config_group')
      expect(driver).to receive(:active_module).and_return(nil)

      expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr
      The following global/module datastore, & databse setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [group/name/1]
      key1=val1
      key2=val2
      key3=val3
      ```

      </details>


      OUTPUT

      expect(subject.datastore(framework, driver)).to eql(expected_output)
    end

    it "correctly retrieves & parses a populated global datastore and current module" do
      allow(::Msf::Config).to receive(:config_file).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'config_files', 'empty.ini'))

      framework = double('framework')
      expect(framework).to receive(:datastore).and_return({
                                                            'key1' => 'val1',
                                                            'key2' => 'val2',
                                                            'key3' => 'val3'
                                                          })


      driver = double('driver')
      expect(driver).to receive(:get_config_core).and_return('group/name/1')
      expect(driver).to receive(:get_config).and_return({
                                                          'key4' => 'val4',
                                                          'key5' => 'val5',
                                                          'key6' => 'val6'
                                                        })
      expect(driver).to receive(:get_config_group).and_return('group/name/2')
      expect(driver).to receive(:active_module).and_return(nil)

      expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr
      The following global/module datastore, & databse setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [group/name/1]
      key1=val1
      key2=val2
      key3=val3

      [group/name/2]
      key4=val4
      key5=val5
      key6=val6
      ```

      </details>


      OUTPUT

      expect(subject.datastore(framework, driver)).to eql(expected_output)
    end

    it "correctly retrieves & parses active module variables " do
      allow(::Msf::Config).to receive(:config_file).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'config_files', 'empty.ini'))

      framework = double('framework')
      expect(framework).to receive(:datastore).and_return({})


      driver = double('driver')
      expect(driver).to receive(:get_config_core).and_return('group/name/1')
      expect(driver).to receive(:get_config).and_return({})
      expect(driver).to receive(:get_config_group).and_return('config_group')


      active_module = double('active_module')
      expect(driver).to receive(:active_module).at_least(7).times.and_return(active_module)
      expect(active_module).to receive(:datastore).and_return({
                                                                'key7' => 'val7',
                                                                'key8' => 'default_val8',
                                                                'key9' => 'val9'
                                                              })
      default_value = double('default_value')
      expect(default_value).to receive(:default).and_return('default_val8')

      default_hash = {'KEY8'=>default_value}
      expect(active_module).to receive(:options).at_least(4).times.and_return(default_hash)
      expect(active_module).to receive(:refname).and_return('active/module/variables')


      expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr
      The following global/module datastore, & databse setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [active/module/variables]
      key7=val7
      key9=val9
      ```

      </details>


      OUTPUT

      expect(subject.datastore(framework, driver)).to eql(expected_output)
    end

    it "correctly retrieves & parses Database information" do
      allow(::Msf::Config).to receive(:config_file).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'config_files', 'db.ini'))

      framework = double('framework')
      expect(framework).to receive(:datastore).and_return({})


      driver = double('driver')
      expect(driver).to receive(:get_config_core).and_return('group/name/1')
      expect(driver).to receive(:get_config).and_return({})
      expect(driver).to receive(:get_config_group).and_return('group/name/2')
      expect(driver).to receive(:active_module).and_return(nil)

      expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr
      The following global/module datastore, & databse setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [framework/database/1]
      key10=val10
      key11=val11

      [framework/database/2]
      key12=val12
      key13=val13
      ```

      </details>


      OUTPUT

      expect(subject.datastore(framework, driver)).to eql(expected_output)
    end

    it "correctly retrieves & parses logs shorter than the log line total" do
      range = 1..30
      logs = ''
      range.each do |i|
        logs += "[00/00/0000 00:00:00] [e(0)] core: Log Line #{i}\n"
      end

      allow(::Msf::Config).to receive(:log_directory).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'framework_logs', 'short'))

      error_log_output = <<~E_LOG
        ##  %grnLogs%clr
        The following logs were recorded before the issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        #{logs.strip}
        ```

        </details>


      E_LOG

      expect(subject.logs).to eql(error_log_output)
    end

    it "correctly retrieves & parses logs equal to the log line total" do
      range = 1..50
      logs = ''
      range.each do |i|
        logs += "[00/00/0000 00:00:00] [e(0)] core: Log Line #{i}\n"
      end

      allow(::Msf::Config).to receive(:log_directory).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'framework_logs', 'equal'))

      error_log_output = <<~E_LOG
        ##  %grnLogs%clr
        The following logs were recorded before the issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        #{logs.strip}
        ```

        </details>


      E_LOG

      expect(subject.logs).to eql(error_log_output)
    end

    it "correctly retrieves & parses logs larger than the log line total" do
      range = 51..100
      logs = ''
      range.each do |i|
        logs += "[00/00/0000 00:00:00] [e(0)] core: Log Line #{i}\n"
      end

      allow(::Msf::Config).to receive(:log_directory).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'framework_logs', 'long'))

      error_log_output = <<~E_LOG
        ##  %grnLogs%clr
        The following logs were recorded before the issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        #{logs.strip}
        ```

        </details>


      E_LOG

      expect(subject.logs).to eql(error_log_output)
    end

    it "correctly retrieves & parses an empty log file" do
      allow(::Msf::Config).to receive(:log_directory).and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'framework_logs', 'empty'))

      error_log_output = <<~E_LOG
        ##  %grnLogs%clr
        The following logs were recorded before the issue occurred:
        <details>
        <summary>Collapse</summary>

        ```
        #{''}
        ```

        </details>


      E_LOG

      expect(subject.logs).to eql(error_log_output)
    end

    it "correctly retrieves version information with no connected DB" do
      framework = double('framework')
      expect(framework).to receive(:version).and_return('VERSION')

      db = double('db')
      expect(framework).to receive(:db).at_least(2).times.and_return(db)
      expect(db).to receive(:connection_established?).and_return(false)
      expect(db).to receive(:driver).and_return('driver')

      allow(::Msf::Config).to receive(:install_root).at_least(3).times.and_return('bad/path')
      RUBY_DESCRIPTION = 'Ruby Description'

      expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr
      The versions & install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: bad/path
      Session Type: driver selected, no connection
      Install Method: Other
      ```

      </details>


      OUTPUT

      expect(subject.versions(framework)).to eql(expected_output)
    end

    it "correctly retrieves version information with DB connected via http" do
      framework = double('framework')
      expect(framework).to receive(:version).and_return('VERSION')

      db = double('db')
      expect(framework).to receive(:db).at_least(2).times.and_return(db)
      expect(db).to receive(:connection_established?).and_return(true)
      expect(db).to receive(:driver).at_least(2).times.and_return('http')
      expect(db).to receive(:name).and_return('db_name')
      expect(db).to receive(:get_data_service).at_least(2).times.and_return('db_data_service')

      allow(::Msf::Config).to receive(:install_root).at_least(3).times.and_return('bad/path')
      RUBY_DESCRIPTION = 'Ruby Description'

      expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr
      The versions & install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: bad/path
      Session Type: Connected to db_name. Connection type: http. Connection name: db_data_service.
      Install Method: Other
      ```

      </details>


      OUTPUT

      expect(subject.versions(framework)).to eql(expected_output)
    end

    it "correctly retrieves version information with DB connected via local connection" do
      framework = double('framework')
      expect(framework).to receive(:version).and_return('VERSION')

      db = double('db')
      expect(framework).to receive(:db).at_least(2).times.and_return(db)
      expect(db).to receive(:connection_established?).and_return(true)
      expect(db).to receive(:driver).at_least(2).times.and_return('local')
      expect(db).to receive(:get_data_service).at_least(2).times.and_return('db_data_service')

      connection = double('connection')
      expect(connection).to receive(:current_database).and_return('current_db_connection')
      expect(connection).to receive(:respond_to?).and_return(true)

      connection_pool = double('connection_pool')
      expect(connection_pool).to receive(:with_connection).and_yield(connection)

      allow(::ActiveRecord::Base).to receive(:connection_pool).and_return(connection_pool)
      allow(::Msf::Config).to receive(:install_root).at_least(3).times.and_return('bad/path')
      RUBY_DESCRIPTION = 'Ruby Description'

      expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr
      The versions & install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: bad/path
      Session Type: Connected to current_db_connection. Connection type: local. Connection name: db_data_service.
      Install Method: Other
      ```

      </details>


      OUTPUT

      expect(subject.versions(framework)).to eql(expected_output)
    end

    it "correctly retrieves version information with no connected DB and a Kali Install" do
      framework = double('framework')
      expect(framework).to receive(:version).and_return('VERSION')

      db = double('db')
      expect(framework).to receive(:db).at_least(2).times.and_return(db)
      expect(db).to receive(:connection_established?).and_return(false)
      expect(db).to receive(:driver).and_return('driver')

      allow(::Msf::Config).to receive(:install_root).at_least(3).times.and_return(File.join(File::SEPARATOR, 'usr', 'share', 'metasploit-framework'))
      RUBY_DESCRIPTION = 'Ruby Description'

      expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr
      The versions & install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: /usr/share/metasploit-framework
      Session Type: driver selected, no connection
      Install Method: Kali
      ```

      </details>


      OUTPUT

      puts expect(subject.versions(framework)).to eql(expected_output)
    end


    it "correctly retrieves version information with no connected DB and a Kali Install" do
      framework = double('framework')
      expect(framework).to receive(:version).and_return('VERSION')

      db = double('db')
      expect(framework).to receive(:db).at_least(2).times.and_return(db)
      expect(db).to receive(:connection_established?).and_return(false)
      expect(db).to receive(:driver).and_return('driver')

      allow(::Msf::Config).to receive(:install_root).at_least(3).times.and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'installs' ,'omnibus'))
      RUBY_DESCRIPTION = 'Ruby Description'

      expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr
      The versions & install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: #{File.join(FILE_FIXTURES_PATH, 'debug', 'installs', 'omnibus')}
      Session Type: driver selected, no connection
      Install Method: Omnibus Installer
      ```

      </details>


      OUTPUT

      puts expect(subject.versions(framework)).to eql(expected_output)
    end

    # TODO: Figure out a way to push a .git folder to the remote repo so this test can detect it
    # it "correctly retrieves version information with no connected DB and a Git Clone" do
    #     framework = double('framework')
    #     expect(framework).to receive(:version).and_return('VERSION')
    #
    #     db = double('db')
    #     expect(framework).to receive(:db).at_least(2).times.and_return(db)
    #     expect(db).to receive(:connection_established?).and_return(false)
    #     expect(db).to receive(:driver).and_return('driver')
    #
    #     allow(::Msf::Config).to receive(:install_root).at_least(3).times.and_return(File.join(FILE_FIXTURES_PATH, 'debug', 'installs'))
    #
    #     expected_output = <<~OUTPUT
    #     ##  %grnVersion/Install%clr
    #     The versions & install method of your Metasploit setup:
    #     <details>
    #     <summary>Collapse</summary>
    #
    #     ```
    #     Framework: VERSION
    #     Ruby: #{RUBY_DESCRIPTION}
    #     Install Root: #{File.join(FILE_FIXTURES_PATH, 'debug', 'installs')}
    #     Session Type: driver selected, no connection
    #     Install Method: Git Clone
    #     ```
    #
    #     </details>
    #
    #
    #     OUTPUT
    #
    #     puts expect(subject.versions(framework)).to eql(expected_output)
    #   end
  end
end
