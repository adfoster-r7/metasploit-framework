require "allure-rspec"

# Patch the Allure RSpec Formatter to support running across multiple Github action workers
class AllureRspec::RSpecFormatter
  #
  # Transform example to <Allure::TestResult>
  # @param [RSpec::Core::Example] example
  # @return [Allure::TestResult]
  # XXX: Patch https://github.com/allure-framework/allure-ruby/blob/ec4f9901f241b177bdd83528e9046cd8646f29de/allure-rspec/lib/allure_rspec/formatter.rb#L99-L116
  def test_result(example)
    parser = AllureRspec::RspecMetadataParser.new(example, allure_config)

    Allure::TestResult.new(
      name: example.description,
      description: "Location - #{strip_relative(example.location)}",
      description_html: "Location - #{strip_relative(example.location)}",
      # XXX: The default example.id behavior i.e. "./spec/acceptance/meterpreter_spec.rb[1:2:1:1:11:1]", doesn't work when running in parallel against different HostOS versions
      # Temporarily namespace this generated history_id to ensure allure reports are generated correctly
      history_id: namespaced_history_id(example),
      full_name: example.full_description,
      labels: parser.labels,
      links: parser.links,
      status_details: parser.status_details,
      environment: allure_config.environment
    )
  end

  def namespaced_history_id(example)
    runtime_environment_metadata = allure_config.environment_properties
    "#{runtime_environment_metadata}_#{example.id}"
  end
end

AllureRspec.configure do |config|
  config.results_directory = "tmp/allure-raw-data"
  config.clean_results_directory = true
  config.logging_level = Logger::INFO
  config.logger = Logger.new($stdout, Logger::DEBUG)
  config.environment = RbConfig::CONFIG['host_os']

  # Add additional metadata to allure
  environment_properties = {
    host_os: RbConfig::CONFIG['host_os'],
    ruby_version: RUBY_VERSION,
    host_runner_image: ENV['HOST_RUNNER_IMAGE'],
  }.compact
  meterpreter_name = ENV['METERPRETER']
  meterpreter_runtime_version = ENV['METERPRETER_RUNTIME_VERSION']
  if meterpreter_name.present?
    environment_properties[:meterpreter_name] = meterpreter_name
    if meterpreter_runtime_version.present?
      environment_properties[:meterpreter_runtime_version] = "#{meterpreter_name}#{meterpreter_runtime_version}"
    end
  end

  config.environment_properties = environment_properties.compact
end
