require 'acceptance_spec_helper'

RSpec.describe 'Meterpreter' do
  include_context 'wait_for_expect'

  # Tests to ensure that Meterpreter is consistent across all implementations/operation systems
  METERPRETER_PAYLOADS = Acceptance::Meterpreter.with_meterpreter_name_merged(
    {
      PYTHON: Acceptance::Meterpreter::PYTHON_METERPRETER,
      # php: Acceptance::Meterpreter::PHP_METERPRETER,
      # Java: Acceptance::Meterpreter::JAVA_METERPRETER,
      # mettle: Acceptance::Meterpreter::METTLE_METERPRETER,
      # windows_meterpreter: Acceptance::Meterpreter::WINDOWS_METERPRETER
    }
  )

  let(:current_platform) { Acceptance::Meterpreter::current_platform }
  let_it_be(:port_generator) { Acceptance::PortGenerator.new }

  # Driver instance, keeps track of all open processes/payloads/etc, so they can be closed cleanly
  let_it_be(:driver) do
    driver = Acceptance::ConsoleDriver.new
    driver
  end

  # Opens a test console with the test loadpath specified
  let_it_be(:console) do
    console = driver.open_console

    # Load the test modules
    console.sendline('loadpath test/modules')
    console.recvuntil(/Loaded \d+ modules:[^\n]*\n/)
    console.recvuntil(/\d+ auxiliary modules[^\n]*\n/)
    console.recvuntil(/\d+ exploit modules[^\n]*\n/)
    console.recvuntil(/\d+ post modules[^\n]*\n/)
    console.recvuntil(Acceptance::Console.prompt)

    # Read the remaining console
    # console.sendline "quit -y"
    # console.recvall

    console
  end

  METERPRETER_PAYLOADS.each do |meterpreter_name, meterpreter_config|
    describe "#{meterpreter_name}#{ENV.fetch('METERPRETER_RUNTIME_VERSION', '')}", focus: meterpreter_config[:focus] do
      meterpreter_config[:payloads].each do |payload_config|
        describe(
          Acceptance::Meterpreter.human_name_for_payload(payload_config).to_s,
          if: (
            Acceptance::Meterpreter.run_meterpreter?(meterpreter_config) &&
              Acceptance::Meterpreter.supported_platform?(payload_config)
          )
        ) do
          let(:payload) { Acceptance::Payload.new(payload_config) }

          let(:session_tlv_logging_file) do
            Acceptance::TempChildProcessFile.new("#{payload.name}_session_tlv_logging", 'txt')
          end

          let(:meterpreter_logging_file) do
            Acceptance::TempChildProcessFile.new('#{payload.name}_debug_log', 'txt')
          end

          let(:default_global_datastore) do
            {
              SessionTlvLogging: "file:#{session_tlv_logging_file.path}"
            }
          end

          let(:default_module_datastore) do
            {
              AutoVerifySessionTimeout: 10,
              MeterpreterDebugLogging: "rpath:#{meterpreter_logging_file.path}"
            }
          end

          # The shared payload session instance that will be reused across the test run
          let(:await_session_id) do
            payload_config[:datastore][:module].merge!({ lport: port_generator.next, lhost: '127.0.0.1' })

            console.sendline "use #{payload.name}"
            console.recvuntil(Acceptance::Console.prompt)

            # Set global options
            console.sendline payload.setg_commands(default_global_datastore: default_global_datastore)
            console.recvuntil(Acceptance::Console.prompt)

            # Generate the payload
            console.sendline payload.generate_command(default_module_datastore: default_module_datastore)
            console.recvuntil(/Writing \d+ bytes[^\n]*\n/)
            generate_result = console.recvuntil(Acceptance::Console.prompt)

            expect(generate_result.lines).to_not include(match('generation failed'))
            wait_for_expect do
              expect(payload.size).to be > 0
            end

            console.sendline 'to_handler'
            console.recvuntil(/Started reverse TCP handler[^\n]*\n/)
            driver.run_payload(payload)

            session_opened_matcher = /Meterpreter session (\d+) opened[^\n]*\n/
            session_message = console.recvuntil(session_opened_matcher)
            session_id = session_message[session_opened_matcher, 1]
            expect(session_id).to_not be_nil

            session_id
          end

          before :each do
            driver.close_payloads
            console.reset
            await_session_id
          end

          after :all do
            driver.close_payloads
            console.reset
          end

          meterpreter_config[:module_tests].each do |module_test|
            describe module_test[:name].to_s do
              it(
                "successfully opens a session for the #{payload_config[:name].inspect} payload and passes the #{module_test[:name].inspect} tests",
                if: (
                  Acceptance::Meterpreter.run_meterpreter?(meterpreter_config) &&
                    Acceptance::Meterpreter.supported_platform?(payload_config) &&
                    Acceptance::Meterpreter.supported_platform?(module_test)
                )
              ) do
                console.sendline("use #{module_test[:name]}")
                console.recvuntil(Acceptance::Console.prompt)

                console.sendline("run session=#{await_session_id} AddEntropy=true Verbose=true")

                # Expect happiness
                test_result = console.recvuntil('Post module execution completed')

                # Ensure there are no failures, and assert tests are complete
                aggregate_failures do
                  acceptable_failures = module_test.dig(:lines, :all, :acceptable_failures) || []
                  acceptable_failures += module_test.dig(:lines, current_platform, :acceptable_failures) || []
                  acceptable_failures = acceptable_failures.flat_map { |value| Acceptance::LineValidation.new(*Array(value)).flatten }

                  required_lines = module_test.dig(:lines, :all, :required) || []
                  required_lines += module_test.dig(:lines, current_platform, :required) || []
                  required_lines = required_lines.flat_map { |value| Acceptance::LineValidation.new(*Array(value)).flatten }

                  # XXX: When debugging failed tests, you can enter into an interactive msfconsole prompt with:
                  # console.interact

                  # Skip any ignored lines from the validation input
                  validated_lines = test_result.lines.reject do |line|
                    is_acceptable = acceptable_failures.any? do |acceptable_failure|
                      line.match?(acceptable_failure.value) &&
                        acceptable_failure.if?
                    end

                    is_acceptable
                  end

                  validated_lines.each do |test_line|
                    test_line = Acceptance::Meterpreter.uncolorize(test_line)
                    expect(test_line).to_not include('FAILED', '[-] FAILED', '[-] Exception', '[-] '), "Unexpected error: #{test_line}"
                  end

                  # Assert all expected lines are present, unless they're flaky
                  required_lines.each do |required|
                    next unless required.if?

                    expect(test_result).to include(required.value)
                  end

                  # Assert all ignored lines are present, if they are not present - they should be removed from
                  # the calling config
                  acceptable_failures.each do |acceptable_failure|
                    next if acceptable_failure.flaky?
                    next unless acceptable_failure.if?

                    expect(test_result).to include(acceptable_failure.value)
                  end
                end
              ensure
                Allure.add_attachment(
                  name: 'payload',
                  source: payload.as_readable_text(
                    default_global_datastore: default_global_datastore,
                    default_module_datastore: default_module_datastore
                  ),
                  type: Allure::ContentType::TXT,
                  test_case: false
                )

                Allure.add_attachment(
                  name: 'payload debug log if available',
                  source: File.exist?(meterpreter_logging_file.path) ? File.binread(meterpreter_logging_file.path) : 'none present',
                  type: Allure::ContentType::TXT,
                  test_case: false
                )

                Allure.add_attachment(
                  name: 'session tlv logging if available',
                  source: File.exist?(session_tlv_logging_file.path) ? File.binread(session_tlv_logging_file.path) : 'empty',
                  type: Allure::ContentType::TXT,
                  test_case: false
                )

                Allure.add_attachment(
                  name: 'console data',
                  source: console.all_data,
                  type: Allure::ContentType::TXT,
                  test_case: false
                )
              end
            end
          end
        end
      end
    end
  end
end
