require 'support/acceptance/meterpreter'

module Acceptance::Meterpreter
  PHP_METERPRETER = {
    payloads: [
      {
        name: "php/meterpreter_reverse_tcp",
        extension: ".php",
        platforms: [:osx, :linux, :windows],
        execute_cmd: ["php", "${payload_path}"],
        generate_options: {
          '-f': "raw"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterDebugBuild: true
          }
        }
      }
    ],
    module_tests: [
      {
        name: "test/services",
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: "Windows only test"
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: "Windows only test"
            }
          ],
          [
            :meterpreter,
            {
              if: [
                :meterpreter_runtime_version,
                :==,
                "php5.3"
              ],
              reason: "Skip PHP 5.3 - as cmd_exec takes 15 seconds for each call, due to failure to detect feof correctly - https://github.com/rapid7/metasploit-payloads/blame/c7f7bc2fc0b86e17c3bc078149c71745c5e478b3/php/meterpreter/meterpreter.php#L1127-L1145"
            }
          ]
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          meterpreter: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: [
              "[-] [should modify config on a given service] FAILED: should modify config on a given service",
              "[-] [should modify config on a given service] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should start a disabled service] FAILED: should start a disabled service",
              "[-] [should start a disabled service] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should restart a started service W32Time] FAILED: should restart a started service W32Time",
              "[-] [should restart a started service W32Time] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should raise a runtime exception if no access to service] FAILED: should raise a runtime exception if no access to service",
              "[-] [should raise a runtime exception if no access to service] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should raise a runtime exception if services doesnt exist] FAILED: should raise a runtime exception if services doesnt exist",
              "[-] [should raise a runtime exception if services doesnt exist] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should start W32Time] FAILED: should start W32Time",
              "[-] [should start W32Time] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should stop W32Time] FAILED: should stop W32Time",
              "[-] [should stop W32Time] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should create a service testes] FAILED: should create a service testes",
              "[-] [should create a service testes] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should return info on the newly-created service testes] Could not retrieve the start type of the testes service!",
              "[-] FAILED: should return info on the newly-created service testes",
              "[-] [should delete the new service testes] FAILED: should delete the new service testes",
              "[-] [should delete the new service testes] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should return status on a given service winmgmt] FAILED: should return status on a given service winmgmt",
              "[-] [should return status on a given service winmgmt] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)"
            ]
          }
        }
      },
      {
        name: "test/cmd_exec",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: [
              "[-] FAILED: should return the stderr output"
            ]
          }
        }
      },
      {
        name: "test/extapi",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/file",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: [
              "[-] FAILED: should read the binary data we just wrote"
            ]
          },
          osx: {
            known_failures: [
              "[-] FAILED: should read the binary data we just wrote"
            ]
          },
          windows: {
            known_failures: [
              "[-] [should delete a symbolic link target] FAILED: should delete a symbolic link target",
              "[-] [should delete a symbolic link target] Exception: Rex::Post::Meterpreter::RequestError : stdapi_fs_delete_dir: Operation failed: 1",
              "[-] FAILED: should read the binary data we just wrote"
            ]
          }
        }
      },
      {
        name: "test/get_env",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/meterpreter",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: [
              "[-] FAILED: should return a list of processes"
            ]
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/railgun",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/railgun_reverse_lookups",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/registry",
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: "Windows only test"
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: "Windows only test"
            }
          ],
          [
            :meterpreter,
            {
              if: [
                :meterpreter_runtime_version,
                :==,
                "php5.3"
              ],
              reason: "Skip PHP 5.3 - as cmd_exec takes 15 seconds for each call, due to failure to detect feof correctly - https://github.com/rapid7/metasploit-payloads/blame/c7f7bc2fc0b86e17c3bc078149c71745c5e478b3/php/meterpreter/meterpreter.php#L1127-L1145"
            }
          ]
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          meterpreter: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: [
              "[-] FAILED: should write REG_EXPAND_SZ values",
              [
                [
                  "[-] [should write REG_MULTI_SZ values] FAILED: should write REG_MULTI_SZ values",
                  "[-] [should write REG_MULTI_SZ values] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should write REG_QWORD values] FAILED: should write REG_QWORD values",
                  "[-] [should write REG_QWORD values] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should write REG_SZ values] FAILED: should write REG_SZ values",
                  "[-] [should write REG_SZ values] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should delete keys] FAILED: should delete keys",
                  "[-] [should delete keys] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should create unicode keys] FAILED: should create unicode keys",
                  "[-] [should create unicode keys] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should write REG_SZ unicode values] FAILED: should write REG_SZ unicode values",
                  "[-] [should write REG_SZ unicode values] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should delete unicode keys] FAILED: should delete unicode keys",
                  "[-] [should delete unicode keys] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should evaluate key existence] FAILED: should evaluate key existence",
                  "[-] [should evaluate key existence] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should read values] FAILED: should read values",
                  "[-] [should read values] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should read values with a 32-bit view] FAILED: should read values with a 32-bit view",
                  "[-] [should read values with a 32-bit view] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should read values with a 64-bit view] FAILED: should read values with a 64-bit view",
                  "[-] [should read values with a 64-bit view] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should return normalized values] FAILED: should return normalized values",
                  "[-] [should return normalized values] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should enumerate keys and values] FAILED: should enumerate keys and values",
                  "[-] [should enumerate keys and values] Exception: Rex::TimeoutError : Send timed out"
                ],
                {
                  if: [
                    :meterpreter_runtime_version,
                    :==,
                    "php5.3"
                  ]
                }
              ]
            ]
          }
        }
      },
      {
        name: "test/search",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/unix",
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Unix only test"
            }
          ]
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      }
    ]
  }
end
