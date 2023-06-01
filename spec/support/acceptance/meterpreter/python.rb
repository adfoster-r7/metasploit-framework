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
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: [
              "[-] FAILED: should start W32Time",
              "[-] Exception: RuntimeError : Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error.",
              "[-] FAILED: should stop W32Time",
              "[-] FAILED: should modify config on a given service",
              "[-] FAILED: should return status on a given service winmgmt",
              "[-] FAILED: should list services",
              "[-] Exception: NoMethodError : undefined method `service' for nil:NilClass",
              "[-] FAILED: should return info on a given service  winmgmt",
              "[-] FAILED: should restart a started service W32Time",
              "[-] FAILED: should start a disabled service",
              "[-] FAILED: should create a service  testes",
              "[-] FAILED: should return info on the newly-created service testes",
              "[-] FAILED: should delete the new service testes"
            ]
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
              "[-] FAILED: should return clipboard jpg dimensions",
              "[-] Exception: NoMethodError : undefined method `clipboard' for nil:NilClass",
              "[-] FAILED: should download clipboard jpg data"
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
              [
                "[-] FAILED: should test for file existence",
                {
                  flaky: true
                }
              ],
              "[-] FAILED: should delete a symbolic link target",
              "[-] Exception: Rex::Post::Meterpreter::RequestError : stdapi_sys_process_execute: Operation failed: Python exception: FileNotFoundError",
              "[-] FAILED: should not recurse into symbolic link directories"
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
                  "[-] FAILED: should return network interfaces",
                  "[-] Exception: Rex::Post::Meterpreter::RequestError : stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError",
                  "[-] FAILED: should have an interface that matches session_host",
                  "[-] FAILED: should return network routes",
                  "[-] Exception: Rex::Post::Meterpreter::RequestError : stdapi_net_config_get_routes: Operation failed: Python exception: TypeError"
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
        name: "test/search",
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
