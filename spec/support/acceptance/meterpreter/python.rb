require 'support/acceptance/meterpreter'

module Acceptance::Meterpreter
  PYTHON_METERPRETER = {
    payloads: [
      {
        name: "python/meterpreter_reverse_tcp",
        extension: ".py",
        platforms: [:osx, :linux, :windows],
        execute_cmd: ["python", "${payload_path}"],
        generate_options: {
          '-f': "raw"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterTryToFork: false,
            PythonMeterpreterDebug: true
          }
        }
      }
    ],
    module_tests: [
      {
        name: "test/meterpreter",
        platforms: [:osx, :linux, :windows],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: []
          },
          linux: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/cmd_exec",
        platforms: [:osx, :linux, :windows],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: []
          },
          linux: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/extapi",
        platforms: [:osx, :linux, :windows],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: []
          },
          linux: {
            known_failures: []
          },
          windows: {
            known_failures: [
              "[-] [should return clipboard jpg dimensions] FAILED: should return clipboard jpg dimensions",
              "[-] [should return clipboard jpg dimensions] Exception: NoMethodError : undefined method `clipboard' for nil:NilClass",
              "[-] [should download clipboard jpg data] FAILED: should download clipboard jpg data",
              "[-] [should download clipboard jpg data] Exception: NoMethodError : undefined method `clipboard' for nil:NilClass"
            ]
          }
        }
      },
      {
        name: "test/file",
        platforms: [:osx, :linux, :windows],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: []
          },
          linux: {
            known_failures: []
          },
          windows: {
            known_failures: [
              "[-] [should delete a symbolic link target] FAILED: should delete a symbolic link target",
              "[-] [should delete a symbolic link target] Exception: Rex::Post::Meterpreter::RequestError : stdapi_sys_process_execute: Operation failed: Python exception: FileNotFoundError",
              "[-] [should not recurse into symbolic link directories] FAILED: should not recurse into symbolic link directories",
              "[-] [should not recurse into symbolic link directories] Exception: Rex::Post::Meterpreter::RequestError : stdapi_sys_process_execute: Operation failed: Python exception: FileNotFoundError",
              [
                "[-] FAILED: should test for file existence",
                {
                  flaky: true
                }
              ]
            ]
          }
        }
      },
      {
        name: "test/get_env",
        platforms: [:osx, :linux, :windows],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: []
          },
          linux: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/meterpreter",
        platforms: [:osx, :linux, :windows],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: [
              [
                [
                  "[-] [should return network interfaces] FAILED: should return network interfaces",
                  "[-] [should return network interfaces] Exception: Rex::Post::Meterpreter::RequestError : stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError",
                  "[-] [should have an interface that matches session_host] FAILED: should have an interface that matches session_host",
                  "[-] [should have an interface that matches session_host] Exception: Rex::Post::Meterpreter::RequestError : stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError"
                ],
                {
                  if: [
                    [
                      :meterpreter_runtime_version,
                      :==,
                      "python3.8"
                    ],
                    :or,
                    [
                      :meterpreter_runtime_version,
                      :==,
                      "python3.6"
                    ]
                  ]
                }
              ]
            ]
          },
          linux: {
            known_failures: []
          },
          windows: {
            known_failures: [
              "[-] FAILED: should return the proper directory separator"
            ]
          }
        }
      },
      {
        name: "test/railgun_reverse_lookups",
        platforms: [:osx, :linux, :windows],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: [
              "[-] FAILED: should return a constant name given a const and a filter",
              "[-] FAILED: should return an error string given an error code"
            ]
          },
          linux: {
            known_failures: [
              "[-] FAILED: should return a constant name given a const and a filter",
              "[-] FAILED: should return an error string given an error code"
            ]
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/unix",
        platforms: [:osx, :linux],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: []
          },
          linux: {
            known_failures: []
          }
        }
      }
    ]
  }
end
