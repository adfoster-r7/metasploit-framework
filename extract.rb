require 'json'
require 'set'

module Acceptance
  module Meterpreter
    # Namespace for following requires
  end
end

$LOAD_PATH << File.expand_path('../../spec')
require 'support/acceptance/meterpreter/java'
require 'support/acceptance/meterpreter/mettle'
require 'support/acceptance/meterpreter/php'
require 'support/acceptance/meterpreter/python'
require 'support/acceptance/meterpreter/windows_meterpreter'

CURRENT_DEFINITIONS = {
  java: Acceptance::Meterpreter::JAVA_METERPRETER,
  mettle: Acceptance::Meterpreter::METTLE_METERPRETER,
  php: Acceptance::Meterpreter::PHP_METERPRETER,
  python: Acceptance::Meterpreter::PYTHON_METERPRETER,
  windows_meterpreter: Acceptance::Meterpreter::WINDOWS_METERPRETER
}

# Could be determined from the allure files, but let's manually curate the list for now
test_files = [
  'test/unix',
  'test/cmd_exec',
  'test/extapi',
  'test/file',
  'test/get_env',
  'test/meterpreter',
  'test/railgun',
  'test/railgun_reverse_lookups',
  'test/registry',
  'test/search',
  'test/services',
]

defaults = {}
 test_files.each do |test_file|
  CURRENT_DEFINITIONS.keys.each do |meterpreter_name|
    defaults[meterpreter_name.to_s] ||= []
    if test_file == 'test/unix'
      platforms = [
        :linux,
        :osx,
        [:windows, { skip: true, reason: 'Unix only test' }]
      ]
    elsif test_file == 'test/services' || test_file == 'test/registry'
      php_meterpreter_skip_windows = [
        :windows,
        skip: [
          :meterpreter_runtime_version,
          :==,
          "php5.3"
        ],
        reason: "Skip PHP 5.3 as the tests timeout - due to cmd_exec taking 15 seconds for each call. Caused by failure to detect feof correctly - https://github.com/rapid7/metasploit-payloads/blame/c7f7bc2fc0b86e17c3bc078149c71745c5e478b3/php/meterpreter/meterpreter.php#L1127-L1145"
      ]

      platforms = [
        [:linux, { skip: true, reason: 'Windows only test'}],
        [:osx, { skip: true, reason: 'Windows only test'}],
        meterpreter_name == :php ? php_meterpreter_skip_windows : :windows
      ]
    elsif meterpreter_name == :windows_meterpreter
      platforms = [
        [:linux, { skip: true, reason: 'Payload not compiled for platform'}],
        [:osx, { skip: true, reason: 'Payload not compiled for platform'}],
        :windows
      ]
    elsif meterpreter_name == :mettle
      platforms = [
        :linux,
        test_file == 'test/search' ? [:osx, skip: true, reason: 'skipped - test/search hangs in osx and CPU spikes to >300%'] : :osx,
        [:windows, { skip: true, reason: 'Payload not compiled for platform'}]
      ]
    else
      platforms = [:linux, :osx, :windows]
    end
    defaults[meterpreter_name.to_s] << {
      name: test_file,
      platforms: platforms,
      skipped: false,
      results: []
    }
  end
end

MANUAL_OVERRIDES = {
}

ALL_PLATFORMS = [:osx, :windows, :linux]

def without_runner_filepath(console_line)
  linux_path = '/home/runner/work/metasploit-framework/'
  mac_path = '/Users/runner/work/metasploit-framework/'
  windows_path = 'D:/a/metasploit-framework/'
  paths_to_omit = [linux_path, mac_path, windows_path]

  result = console_line
  paths_to_omit.each do |omit_path|
    callstack_prefix = /\[-\]\s+#{omit_path}/

    if result.match?(callstack_prefix)
      result = console_line.gsub(callstack_prefix, '')
    end
  end

  paths_to_omit.each do |omit_path|
    if result.include? omit_path
      raise "Found runner path in result #{result}"
    end
  end

  result
end

def as_platform(host_os)
  case host_os
  when /darwin/
    :osx
  when /mingw/
    :windows
  when /linux/
    :linux
  else
    raise "unknown host_os #{host_os.inspect}"
  end
end

def meterpreter_name?(string)
  ['java', 'python', 'mettle', 'php', 'mettle', 'windows_meterpreter'].include?(string)
end

def uuid?(string)
  uuid_regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
  uuid_regex.match?(string)
end

def console_data_attachment_path?(string)
  uuid_regex_prefix = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i
  path_regex = /#{uuid_regex_prefix}-attachment\.txt/i
  path_regex.match?(string)
end

def failure_line?(line)
  ['FAILED', '[-] FAILED', '[-] Exception', '[-] '].any? { |search_term| line.include?(search_term) }
end

def find_or_create_test_metadata_entry!(parent_array, test_name)
  entry = parent_array.find { |array| array[:name] == test_name }
  entry
end

def format_ruby_hash(value, indent_level: 0)
  case value
  when String, Symbol
    value.inspect
  when TrueClass, FalseClass, Numeric
    value.to_s
  when NilClass
    "nil"
  when Array
    if value.empty?
      return "[]"
    end

    result = +"[\n"
    parent_indent_space = '  ' * (indent_level)
    child_indent_space = '  ' * (indent_level + 1)
    result << value.map do |value|
      "#{child_indent_space}#{format_ruby_hash(value, indent_level: indent_level + 1)}"
    end.join(",\n")
    result << "\n#{parent_indent_space}]"
  when Hash
    if value.empty?
      return "{}"
    end

    result = +"{\n"
    parent_indent_space = '  ' * (indent_level)
    child_indent_space = '  ' * (indent_level + 1)
    result << value.map do |key, value|
      key_string = key.to_s.include?('-') ? "'#{key}'" : key.to_s
      is_single_line_formatting = \
        key == :execute_cmd ||
          (key == :platforms && value.all? { |element| element.is_a?(Symbol) })
      value_string = is_single_line_formatting ? value.inspect : format_ruby_hash(value, indent_level: indent_level + 1)

      "#{child_indent_space}#{key_string}: #{value_string}"
    end.join(",\n")
    result << "\n#{parent_indent_space}}"
  else
    raise "Unexpected class #{value.class}"
  end
end

# @param [String] console_output The raw msfconsole output
# @return [Array] the lines associated with the module run
def extract_module_output(console_output)
  # Grab all lines between the `run` command, and the module result
  # Example:
  # msf6 post(test/unix) > run session=2 AddEntropy=true Verbose=true
  # [*] Running against session 2
  # [*] Session type is meterpreter and platform is osx
  # [+] should list users
  # [*] Testing complete in 0.057546
  # [*] Passed: 1; Failed: 0
  # [*] Post module execution completed

  state = :not_found
  result = []
  console_output.lines.each do |line|
    case state
    when :not_found
      if line.include?('run session=')
        state = :reading_module_output
      else
        state = :not_found
      end
    when :reading_module_output
      if line.include? 'Post module execution completed'
        state = :finished
      else
        result << line.rstrip unless line.match?(/Passed: \d+; Failed: \d+/)
        state = :reading_module_output
      end
    when :finished
      # noop
      state = :finished
    end
  end

  result
end

meterpreter_test_suites = {
  **defaults
}

available_reports = Dir['gh-actions-*/raw-data-*'].sort.map { |path| File.expand_path(path) }
available_reports.each do |report_path|
  # Example: "host_os=darwin19\nruby_version=3.0.2\nmeterpreter_name=python\nmeterpreter_runtime_version=python2.7\n"
  environment_properties_raw = File.binread(File.join(report_path, 'environment.properties'))
  # Example: { host_os: '...', .... }
  environment_properties = environment_properties_raw.lines(chomp: true).map { |line| line.split('=', 2) }.to_h.transform_keys(&:to_sym)

  host_os = environment_properties[:host_os]
  meterpreter_name = environment_properties[:meterpreter_name]
  raise "unknown meterpreter name #{meterpreter_name}" if !meterpreter_name?(meterpreter_name)
  meterpreter_version = environment_properties[:meterpreter_runtime_version]

  platform = as_platform(host_os)

  # Map of test name to the file contents as json
  allure_result_containers = Dir["#{report_path}/*-container.json"].sort.each_with_object({}) do |path, result|
    content = JSON.parse(File.binread(path))
    name = content['name']
    next unless test_files.include?(name)

    if result.key?('name')
      raise "Found duplicate container name #{name} for path #{path}"
    end

    # Resolve the child and attachments, assuming there's only one
    if content['children'].length != 1
      require 'pry-byebug'; binding.pry
      raise "unexpected children, expected one #{content.inspect}"
    end
    child_source = content['children'][0]
    raise "Unexpected child path #{child_source} - expected a UUID" if !uuid?(child_source)
    child_content = JSON.parse(File.binread(File.join(report_path, "#{child_source}-result.json")))

    # Read the attachment data
    console_data_attachment = child_content['attachments'].find { |attachment| attachment['name'] == 'console data' }
    if !console_data_attachment
      $stderr.puts "Error: Didn't find console log for #{[host_os, meterpreter_name, meterpreter_version,platform,name] }"
      next
    end
    console_data_attachment_path = console_data_attachment['source']
    raise "Unexpected attachment path #{console_data_attachment_path} - expected a UUID" if !console_data_attachment_path?(console_data_attachment_path)

    console_data_attachment = File.binread(File.join(report_path, console_data_attachment_path))
    result[name] = {
      name: name,
      attachments: {
        console_output: console_data_attachment
      }
    }
  end

  # Find the container for our tests, so that we can view the results. Example:
  # {
  #   "uuid": "5c5f4360-e08e-013b-1799-005056a736a3",
  #   "name": "test/unix",
  #   "children": [
  #     "5c5fa3c0-e08e-013b-1799-005056a736a3" <-- Contains the test results
  #   ],
  #   "befores": [],
  #   "afters": [],
  #   "links": [],
  #   "start": 1685392566565,
  #   "stop": 1685392601033
  # }
  test_files.each do |test_file|
    allure_test_results = allure_result_containers[test_file]
    if !allure_test_results
      $stderr.puts "Warning: #{host_os} #{meterpreter_version} missing #{test_file}"
      next
    end

    # Find the appropriate test entry
    meterpreter_test_suites[meterpreter_name] ||= []
    test_metadata_entry = find_or_create_test_metadata_entry!(meterpreter_test_suites[meterpreter_name], test_file)

    # Open the attachments and start finding failures that appeared in the console
    console_output = allure_test_results[:attachments][:console_output]
    module_output = extract_module_output(console_output)

    failure_lines = module_output
                      .select { |line| failure_line?(line) }
                      .map { |line| without_runner_filepath(line) }

    results = test_metadata_entry[:results]
    results << {
      environment: {
        **environment_properties,
        platform: platform
      },
      failure_lines: failure_lines
    }
  end
end


# @param [Array] predicates, i.e. [[:foo, :==, 123], [:bar, :== 567]]
# @return [Array] The series of predicates converted to infix OR [[:foo, :==, 123], :or, [:bar, :== 567]]
def convert_to_or_statements(predicates)
  return predicates.first if predicates.length == 1

  result = []
  predicates.each do |predicate|
    result << :or if result.length >= 1
    result << predicate
  end
  result
end

# Take the separate meterpreter runtime failures, sort into flaky or not, and try to condense different OS/Linux/Windows outputs into `:all`
def condense_failure_lines(test_suite)
  test_results = test_suite[:results]

  lines_result = test_results.each_with_object({}) do |test_result, final_result|
    platform = test_result[:environment][:platform]
    final_result[platform] ||= {}
    final_result[platform][:known_failures] ||= []
    known_failures = final_result[platform][:known_failures]

    # If it's the first time we've seen this failure; we need to cross-reference and calculate the type of failure it is
    test_result[:failure_lines].each do |failure_line|
      is_previously_seen_failure_line = known_failures.any? { |line| line == failure_line || line[0] == failure_line }
      # We've seen the failure before, ignore it and move on
      next if is_previously_seen_failure_line

      # Additional metadata on the failure line, i.e. flaky, runtime requirements, etc
      failure_metadata = {}

      # Calculate environment specific failures, i.e. the failure didn't occur in different runtime versions/hosts
      other_runtimes = test_results.select do |other_test_result|
        # Same host os, but different runtime/host version
        other_test_result != test_result && (
          other_test_result[:environment][:host_os] == test_result[:environment][:host_os] &&
            (other_test_result[:environment][:meterpreter_runtime_version] != test_result[:environment][:meterpreter_runtime_version] ||
            other_test_result[:environment][:host_runner_image] != test_result[:environment][:host_runner_image])
        )
      end.uniq

      # if failure_line == '[-] FAILED: should return network interfaces'
      #   require 'pry-byebug'; binding.pry
      # end

      other_runtimes_that_include_the_failure = other_runtimes.select do |other_runtime|
        other_runtime[:failure_lines].include?(failure_line)
      end
      if other_runtimes_that_include_the_failure.length != other_runtimes.length
        requirements = (other_runtimes_that_include_the_failure + [test_result]).map do |runtime|
          if runtime[:environment][:meterpreter_runtime_version]
            [:meterpreter_runtime_version, :==, runtime[:environment][:meterpreter_runtime_version]]
          elsif runtime[:environment][:host_runner_image]
            [:host_runner_image, :==, runtime[:environment][:host_runner_image]]
          else
            raise "invalid runtime #{runtime}"
          end
        end

        failure_metadata[:if] = convert_to_or_statements(requirements) if requirements.any?
      end

      # Calculate flakys - i.e. across the _same_ host and version, the failure line appeared sometimes there, and sometimes not there
      same_environments = test_results.select do |other_test_result|
        # Exact environment match, that isn't the current test result
        other_test_result != test_result && other_test_result[:environment] == test_result[:environment]
      end

      is_flaky = same_environments.any? do |other_test_result|
        # If the other identical test environments don't have the failure line present, it must be flakey
        !other_test_result[:failure_lines].include?(failure_line)
      end
      if is_flaky
        failure_metadata[:flaky] = true
        # Prioritize using only flakiness, instead of the more granular `if` values
        failure_metadata.delete(:if)
      end

      known_failures << [failure_line, failure_metadata]
    end
  end

  # Final pass - simplify metadata lines i.e. multiple line failures with the same metadata can be condensed into one array for readability
  simplified_line_results = lines_result.map do |platform, line_config|
    lines_grouped_by_metadata = line_config[:known_failures].group_by { |value| value[1] }

    simplified_failure_lines = []
    lines_grouped_by_metadata.each do |metadata, lines_and_metadata|
      line_strings = lines_and_metadata.map { |lines_and_metadata| lines_and_metadata[0] }
      if metadata.empty?
        simplified_failure_lines.concat(line_strings)
      elsif metadata[:flaky]
        simplified_failure_lines.concat(lines_and_metadata)
      else
        simplified_failure_lines << [line_strings.length == 1 ? line_strings[0] : line_strings, metadata]
      end
    end

    new_line_config = {
      **line_config,
      known_failures: simplified_failure_lines
    }
    [platform, new_line_config]
  end.to_h

  simplified_line_results
end

meterpreter_test_suites.each do |_meterpreter_name, test_suites|
  test_suites.each do |test_suite|
    test_suite[:lines] = condense_failure_lines(test_suite)
    # Add blanks for each missing platform
    test_suite[:platforms].each do |platform|
      platform = platform.is_a?(Array) ? platform[0] : platform
      test_suite[:lines][platform] ||= {}
      test_suite[:lines][platform][:known_failures] ||= []
    end
    test_suite[:lines] = test_suite[:lines].to_a.sort_by { |k, _v| k }.to_h
    test_suite.delete(:results)
  end
end

def merge_overrides!(meterpreter_name, test_suite)
  overrides = MANUAL_OVERRIDES[meterpreter_name.to_sym]
  return test_suite unless overrides

  overrides.each do |override|
    target_test_suite = test_suite.find { |test_suite| test_suite['name'] == override['name'] }
    target_test_suite.merge!(override)
  end

  test_suite
end

meterpreter_test_suites.each do |meterpreter_name, test_suite|
  config = {
    payloads: CURRENT_DEFINITIONS[meterpreter_name.to_sym][:payloads],
    module_tests: merge_overrides!(meterpreter_name, test_suite).sort_by { |test_suite| test_suite['name'] }
  }

  content = <<~EOF
    require 'support/acceptance/meterpreter'

    module Acceptance::Meterpreter
      #{meterpreter_name.upcase.gsub('_METERPRETER', '')}_METERPRETER = #{format_ruby_hash(config, indent_level: 1)}
    end
  EOF

  puts <<~EOF
    #{meterpreter_name.upcase}
    ===================
    #{content}
  EOF

  File.binwrite("extraction/#{meterpreter_name}.rb", content)
rescue => e
  require 'pry-byebug'; binding.pry
end
