require 'support/acceptance/meterpreter'

module Acceptance::Meterpreter
  WINDOWS_METERPRETER = {
    payloads: [
      {
        name: "windows/meterpreter/reverse_tcp",
        extension: ".exe",
        platforms: [:windows],
        execute_cmd: ["${payload_path}"],
        executable: true,
        generate_options: {
          '-f': "exe"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterTryToFork: false,
            MeterpreterDebugBuild: true
          }
        }
      }
    ],
    module_tests: [
      {
        name: "test/services",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/extapi",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: [
              "[-] FAILED: should return an array of clipboard data",
              "[-] Exception: TypeError : no implicit conversion of Symbol into Integer",
              "[-] FAILED: should return clipboard jpg dimensions",
              "[-] FAILED: should set clipboard text",
              "[-] FAILED: should download clipboard text data",
              "[-] FAILED: should download clipboard jpg data"
            ]
          }
        }
      },
      {
        name: "test/file",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/get_env",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/meterpreter",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/railgun",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/railgun_reverse_lookups",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/registry",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/search",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/cmd_exec",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: []
          }
        }
      }
    ]
  }
end
