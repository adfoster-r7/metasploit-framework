require 'fileutils'
require 'rbconfig'
require 'tmpdir'
require 'msfdb_helpers/pg_ctl'
require 'msfdb_helpers/pg_ctlcluster'

RSpec.describe MsfdbHelpers::PgCtl do
  let(:root) { Dir.mktmpdir('msfdb-spec-') }
  let(:db_path) { File.join(root, 'db') }
  let(:db_conf) { File.join(root, 'database.yml') }
  let(:options) do
    {
      msf_db_name: 'msf', msf_db_user: 'msf', msftest_db_name: 'msftest', msftest_db_user: 'msftest',
      db_host: '127.0.0.1', db_port: 5433, db_pool: 200, debug: false
    }
  end
  let(:cluster) { described_class.new(db_path: db_path, localconf: root, db_conf: db_conf, options: options) }
  let(:hba_path) { File.join(db_path, 'pg_hba.conf') }
  let(:legacy_hba) do
    <<~HBA
      host "msf" "msf" 127.0.0.1/32 md5
      host "msftest" "msftest" 127.0.0.1/32 md5
      host "postgres" "msftest" 127.0.0.1/32 md5
      host "template1" all 127.0.0.1/32 trust
      local all all trust
    HBA
  end

  before do
    stub_const('DatabaseStatus', Class.new)
    DatabaseStatus.const_set(:RUNNING, 0)
    DatabaseStatus.const_set(:INACTIVE, 1)
    DatabaseStatus.const_set(:NOT_FOUND, 2)
  end

  after do
    FileUtils.remove_entry(root) if File.exist?(root)
  end

  describe '#secure' do
    before do
      Dir.mkdir(db_path, 0o700)
      File.write(hba_path, legacy_hba)
    end

    it 'removes the generated trust rules and restarts a running cluster' do
      running = true
      allow(cluster).to receive(:status) { running ? DatabaseStatus::RUNNING : DatabaseStatus::INACTIVE }
      allow(cluster).to receive(:stop_cluster) {
                          running = false
                          true
                        }
      allow(cluster).to receive(:start_cluster) {
                          running = true
                          true
                        }

      expect(cluster.secure).to be(true)
      expect(File.read(hba_path)).to eq(legacy_hba.lines.first(3).join)
      expect(running).to be(true)
    end

    it 'leaves a stopped cluster stopped' do
      allow(cluster).to receive(:status).and_return(DatabaseStatus::INACTIVE)
      expect(cluster).not_to receive(:start_cluster)

      cluster.secure
      expect(File.read(hba_path)).not_to include('trust')
    end

    it 'preserves custom trust rules and does not stop the database' do
      File.write(hba_path, legacy_hba + "host all all 192.0.2.0/24 trust\n")
      expect(cluster).not_to receive(:stop_cluster)

      expect { cluster.secure }.to raise_error(MsfdbHelpers::SecurityError, /custom trust rules/)
      expect(File.read(hba_path)).to include('192.0.2.0/24 trust')
    end

    it 'preserves password rules with comments mentioning trust' do
      custom_rule = "host \"msf#data\" \"msf\" 127.0.0.1/32 md5 # avoid trust\n"
      File.write(hba_path, legacy_hba + custom_rule)
      allow(cluster).to receive(:status).and_return(DatabaseStatus::INACTIVE)

      cluster.secure
      expect(File.read(hba_path)).to include(custom_rule)
    end

    it 'requires manual review of included authentication files' do
      File.write(hba_path, legacy_hba + "include_if_exists 'extra.conf'\n")
      expect(cluster).not_to receive(:stop_cluster)

      expect { cluster.secure }.to raise_error(MsfdbHelpers::SecurityError, /includes other files/)
    end

    it 'removes legacy Windows loopback trust rules' do
      File.write(hba_path, legacy_hba + "host all all 127.0.0.1/32 trust\nhost all all ::1/128 trust\n")
      allow(cluster).to receive(:status).and_return(DatabaseStatus::INACTIVE)

      cluster.secure
      expect(File.read(hba_path)).not_to include('trust')
    end

    it 'keeps the secure file if restart fails' do
      allow(cluster).to receive(:status).and_return(DatabaseStatus::RUNNING, DatabaseStatus::RUNNING, DatabaseStatus::INACTIVE)
      allow(cluster).to receive(:stop_cluster).and_return(true)
      allow(cluster).to receive(:start_cluster).and_return(false)

      expect { cluster.secure }.to raise_error(MsfdbHelpers::SecurityError, /could not restart/)
      expect(File.read(hba_path)).not_to include('trust')
    end
  end

  describe 'initialization' do
    before do
      allow(cluster).to receive(:server_version).and_return('15')
      allow(PG).to receive(:library_version).and_return(150_000)
    end

    it 'reuses already-created roles and databases during bootstrap' do
      connection = instance_double(PG::Connection)
      role_result = instance_double(PG::Result, any?: true)
      database_result = instance_double(PG::Result, any?: true, getvalue: 'msf')
      allow(PG).to receive(:connect).and_yield(connection)
      allow(connection).to receive(:quote_ident) { |value| "\"#{value}\"" }
      allow(connection).to receive(:escape_literal) { |value| "'#{value}'" }
      allow(connection).to receive(:exec_params).with(/pg_roles/, anything).and_return(role_result)
      allow(connection).to receive(:exec_params).with(/pg_database/, anything).and_return(database_result)
      allow(connection).to receive(:exec)

      cluster.send(:create_database_users!, 'bootstrap-password', 'app-password', 'test-password')

      expect(connection).to have_received(:exec).with(/ALTER ROLE "msf" .*PASSWORD 'app-password'/)
      expect(connection).not_to have_received(:exec).with(/CREATE DATABASE/)
    end

    it 'rejects an old libpq before creating a checkpoint or cluster' do
      allow(PG).to receive(:library_version).and_return(90_600)

      expect { cluster.init('app-password', 'test-password') }.to raise_error(MsfdbHelpers::SecurityError, /SCRAM/)
      expect(File).not_to exist(db_path)
      expect(cluster.pending_initialization?).to be(false)
    end

    it 'rejects system database names before creating cluster files' do
      options[:msf_db_name] = 'postgres'

      expect { cluster.init('app-password', 'test-password') }.to raise_error(MsfdbHelpers::SecurityError, /PostgreSQL system names/)
      expect(File).not_to exist(db_path)
      expect(cluster.pending_initialization?).to be(false)
    end

    it 'prevents concurrent initialization of the same profile' do
      cluster.with_initialization_lock do
        expect { cluster.with_initialization_lock { nil } }.to raise_error(MsfdbHelpers::SecurityError, /Another database initialization/)
      end
    end

    it 'rejects an invalid initialization checkpoint' do
      checkpoint = File.join(root, '.msfdb-initialization.json')
      File.write(checkpoint, '[]')
      File.chmod(0o600, checkpoint)

      expect { cluster.initialization_credentials }.to raise_error(MsfdbHelpers::SecurityError, /checkpoint is invalid/)
    end

    context 'when cluster setup is interrupted' do
      before do
        running = false
        allow(cluster).to receive(:status) do
          if running
            DatabaseStatus::RUNNING
          elsif File.exist?(db_path)
            DatabaseStatus::INACTIVE
          else
            DatabaseStatus::NOT_FOUND
          end
        end
        allow(cluster).to receive(:start_cluster) {
                            running = true
                            true
                          }
        allow(cluster).to receive(:stop_cluster) {
                            running = false
                            true
                          }
        allow(cluster).to receive(:initialize_cluster) do
          File.write(File.join(db_path, 'PG_VERSION'), '15')
          File.write(File.join(db_path, 'postgresql.conf'), '')
          File.write(hba_path, '')
          File.write(File.join(db_path, 'preserved-data'), 'kept')
        end
        allow(cluster).to receive(:verify_connections!)
      end

      it 'resumes role creation with the original passwords and preserves existing data' do
        attempts = 0
        allow(cluster).to receive(:create_database_users!) do
          attempts += 1
          raise MsfdbHelpers::SecurityError, 'interrupted' if attempts == 1
        end

        expect { cluster.init('app-password', 'test-password') }.to raise_error(MsfdbHelpers::SecurityError, /interrupted/)
        expect(cluster.pending_initialization?).to be(true)
        expect { cluster.start }.to raise_error(MsfdbHelpers::SecurityError, /initialization is incomplete/)
        expect(File.stat(File.join(root, '.msfdb-initialization.json')).mode & 0o777).to eq(0o600)
        expect(cluster.init('different', 'different')).to be(true)
        expect(cluster).to have_received(:create_database_users!).with(anything, 'app-password', 'test-password').twice
        expect(File.read(File.join(db_path, 'preserved-data'))).to eq('kept')
        expect(cluster.initialization_credentials).to include(msf_password: 'app-password', msftest_password: 'test-password')
        cluster.complete_initialization!
        expect(cluster.pending_initialization?).to be(false)
      end

      it 'resumes configuration after cluster creation without rerunning initdb' do
        attempts = 0
        allow(cluster).to receive(:create_database_users!)
        allow(cluster).to receive(:configure_server!).and_wrap_original do |method, **kwargs|
          attempts += 1
          raise MsfdbHelpers::SecurityError, 'interrupted' if attempts == 1

          method.call(**kwargs)
        end
        expect { cluster.init('app-password', 'test-password') }.to raise_error(MsfdbHelpers::SecurityError, /interrupted/)
        expect(cluster).not_to receive(:initialize_cluster)

        expect(cluster.init('app-password', 'test-password')).to be(true)
      end

      it 'preserves an ambiguous partial cluster for manual review' do
        allow(cluster).to receive(:initialize_cluster) do
          File.write(File.join(db_path, 'partial-data'), 'kept')
          raise MsfdbHelpers::SecurityError, 'interrupted'
        end
        expect { cluster.init('app-password', 'test-password') }.to raise_error(MsfdbHelpers::SecurityError, /interrupted/)

        expect { cluster.init('app-password', 'test-password') }.to raise_error(MsfdbHelpers::SecurityError, /inspect the partial cluster/)
        expect(File.read(File.join(db_path, 'partial-data'))).to eq('kept')
      end

      it 'resumes the final authentication transition without recreating roles' do
        allow(cluster).to receive(:create_database_users!)
        allow(cluster).to receive(:write_db_client_auth_config).and_wrap_original do |method, *args, **kwargs|
          raise MsfdbHelpers::SecurityError, 'interrupted' unless kwargs[:bootstrap]

          method.call(*args, **kwargs)
        end
        expect { cluster.init('app-password', 'test-password') }.to raise_error(MsfdbHelpers::SecurityError, /interrupted/)
        allow(cluster).to receive(:write_db_client_auth_config).and_call_original
        expect(cluster).not_to receive(:create_database_users!)

        expect(cluster.init('app-password', 'test-password')).to be(true)
        expect(File.read(hba_path)).not_to include('"postgres" scram-sha-256')
      end
    end
  end

  describe 'socket directories' do
    it 'uses a short owner-only directory for a long profile path' do
      long_root = File.join(root, 'a' * 80)
      FileUtils.mkdir_p(long_root)
      driver = described_class.new(db_path: File.join(long_root, 'db'), localconf: long_root, db_conf: db_conf, options: options)
      directory = driver.send(:ensure_socket_directory!)

      expect("#{directory}/.s.PGSQL.5433".bytesize).to be <= 90
      expect(File.stat(directory).mode & 0o777).to eq(0o700)
    ensure
      Dir.rmdir(directory) if directory && File.directory?(directory)
    end

    it 'uses a simple socket directory when the profile path contains a comma' do
      comma_root = File.join(root, 'with,comma')
      FileUtils.mkdir_p(File.join(comma_root, 'db'))
      driver = described_class.new(db_path: File.join(comma_root, 'db'), localconf: comma_root, db_conf: db_conf, options: options)
      File.write(File.join(comma_root, 'db', 'postgresql.conf'), '')

      driver.send(:configure_server!, authentication: 'scram-sha-256')
      directory = driver.send(:socket_directory)
      expect(directory).not_to include(',')
      expect(File.read(File.join(comma_root, 'db', 'postgresql.conf'))).to include("unix_socket_directories = '#{directory}'")
    ensure
      driver.cleanup_socket_directory if driver && directory
    end

    it 'rejects a symbolic link in place of the private socket directory' do
      long_root = File.join(root, 'b' * 80)
      FileUtils.mkdir_p(long_root)
      driver = described_class.new(db_path: File.join(long_root, 'db'), localconf: long_root, db_conf: db_conf, options: options)
      directory = driver.send(:socket_directory)
      File.symlink(root, directory)

      expect { driver.send(:ensure_socket_directory!) }.to raise_error(MsfdbHelpers::SecurityError, /not owned and restricted/)
    ensure
      File.unlink(directory) if directory && File.symlink?(directory)
    end
  end

  describe 'private file publication' do
    it 'applies the Windows ACL to an empty staging directory before writing credentials' do
      allow(Gem).to receive(:win_platform?).and_return(true)
      allow(cluster).to receive(:windows_sid).and_return('S-1-5-21-1000')
      allow(cluster).to receive(:run_cmd) do |arguments|
        if File.directory?(arguments[1])
          expect(Dir.children(arguments[1])).to be_empty
          expect(arguments).to include('/inheritance:r', '*S-1-5-21-1000:(OI)(CI)F')
        else
          expect(File.size(arguments[1])).to eq(0)
          expect(arguments).to include('/inheritance:r', '*S-1-5-21-1000:F')
        end
        0
      end

      cluster.write_private_file(db_conf, 'credential')
      expect(File.read(db_conf)).to eq('credential')
    end

    it 'does not publish credentials if the Windows file ACL cannot be protected' do
      allow(Gem).to receive(:win_platform?).and_return(true)
      allow(cluster).to receive(:windows_sid).and_return('S-1-5-21-1000')
      allow(cluster).to receive(:run_cmd) { |arguments| File.directory?(arguments[1]) ? 0 : 1 }

      expect { cluster.write_private_file(db_conf, 'credential') }.to raise_error(MsfdbHelpers::SecurityError, /credential file/)
      expect(File).not_to exist(db_conf)
    end
  end
end

RSpec.describe MsfdbHelpers::PgCtlcluster do
  it 'forwards the private configuration root and the failure-output option' do
    Dir.mktmpdir('msfdb-cluster-spec-') do |root|
      db_path = File.join(root, 'db')
      Dir.mkdir(db_path)
      File.write(File.join(db_path, 'PG_VERSION'), '15')
      driver = described_class.new(db_path: db_path, localconf: root, db_conf: File.join(root, 'database.yml'), options: {})
      command = [RbConfig.ruby, '-e', '$stderr.puts ENV.fetch("PG_CLUSTER_CONF_ROOT"); exit 1']

      expect { driver.run_cmd(command, show_output_on_failure: true) }
        .to output("#{File.join(root, '.local', 'etc', 'postgresql')}\n").to_stderr
    end
  end
end
