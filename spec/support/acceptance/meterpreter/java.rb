require 'support/acceptance/meterpreter'

module Acceptance::Meterpreter
  JAVA_METERPRETER = {
    payloads: [
      {
        name: "java/meterpreter/reverse_tcp",
        extension: ".jar",
        platforms: [:osx, :linux, :windows],
        execute_cmd: ["java", "-jar", "${payload_path}"],
        generate_options: {
          '-f': "jar"
        },
        datastore: {
          global: {},
          module: {
            spawn: 0
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
            known_failures: [
              "[-] [should start W32Time] FAILED: should start W32Time",
              "[-] [should start W32Time] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should stop W32Time] FAILED: should stop W32Time",
              "[-] [should stop W32Time] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should list services] FAILED: should list services",
              "[-] [should return info on a given service  winmgmt] FAILED: should return info on a given service  winmgmt",
              "[-] [should create a service  testes] FAILED: should create a service  testes",
              "[-] [should create a service  testes] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should return info on the newly-created service testes] FAILED: should return info on the newly-created service testes",
              "[-] [should delete the new service testes] FAILED: should delete the new service testes",
              "[-] [should delete the new service testes] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should return status on a given service winmgmt] FAILED: should return status on a given service winmgmt",
              "[-] [should return status on a given service winmgmt] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should modify config on a given service] FAILED: should modify config on a given service",
              "[-] [should modify config on a given service] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should start a disabled service] FAILED: should start a disabled service",
              "[-] [should start a disabled service] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should restart a started service W32Time] FAILED: should restart a started service W32Time",
              "[-] [should restart a started service W32Time] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should raise a runtime exception if no access to service] FAILED: should raise a runtime exception if no access to service",
              "[-] [should raise a runtime exception if no access to service] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should raise a runtime exception if services doesnt exist] FAILED: should raise a runtime exception if services doesnt exist",
              "[-] [should raise a runtime exception if services doesnt exist] Exception: Rex::Post::Meterpreter::RequestError : stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              [
                "[-] [should list services] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                {
                  flaky: true
                }
              ],
              [
                "[-] [should return info on a given service  winmgmt] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                {
                  flaky: true
                }
              ],
              [
                "[-] [should return info on the newly-created service testes] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                {
                  flaky: true
                }
              ],
              [
                "[-] [should list services] Exception: Rex::TimeoutError : Send timed out",
                {
                  flaky: true
                }
              ],
              [
                "[-] [should return info on a given service  winmgmt] Exception: Rex::TimeoutError : Send timed out",
                {
                  flaky: true
                }
              ],
              [
                "[-] [should return info on the newly-created service testes] Exception: Rex::TimeoutError : Send timed out",
                {
                  flaky: true
                }
              ]
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
            known_failures: []
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
            known_failures: [
              [
                "[-] FAILED: should append binary data",
                {
                  flaky: true
                }
              ],
              [
                "[-] [should append text files] Didn't read what we wrote, actual file on target:",
                {
                  flaky: true
                }
              ],
              [
                "[-] FAILED: should append text files",
                {
                  flaky: true
                }
              ]
            ]
          },
          windows: {
            known_failures: [
              "[-] [should delete a symbolic link target] failed to create the symbolic link"
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
        name: "test/registry",
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: [
              "[-] FAILED: should write REG_EXPAND_SZ values",
              "[-] FAILED: should write REG_SZ unicode values"
            ]
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
