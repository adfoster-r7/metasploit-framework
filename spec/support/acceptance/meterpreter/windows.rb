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
              "[-] [should return an array of clipboard data] FAILED: should return an array of clipboard data",
              "[-] [should return an array of clipboard data] Exception: TypeError : no implicit conversion of Symbol into Integer",
              "[-] [should return clipboard jpg dimensions] FAILED: should return clipboard jpg dimensions",
              "[-] [should return clipboard jpg dimensions] Exception: TypeError : no implicit conversion of Symbol into Integer",
              "[-] [should set clipboard text] FAILED: should set clipboard text",
              "[-] [should set clipboard text] Exception: TypeError : no implicit conversion of Symbol into Integer",
              "[-] [should download clipboard text data] FAILED: should download clipboard text data",
              "[-] [should download clipboard text data] Exception: TypeError : no implicit conversion of Symbol into Integer",
              "[-] [should download clipboard jpg data] FAILED: should download clipboard jpg data",
              "[-] [should download clipboard jpg data] Exception: TypeError : no implicit conversion of Symbol into Integer"
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
