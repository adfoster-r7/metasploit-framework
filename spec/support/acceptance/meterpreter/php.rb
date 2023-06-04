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
          :windows
        ],
        skipped: false,
        lines: {
          windows: {
            known_failures: [
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
              "[-] [should return status on a given service winmgmt] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should modify config on a given service] FAILED: should modify config on a given service",
              "[-] [should modify config on a given service] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)"
            ]
          },
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          }
        }
      },
      {
        name: "test/cmd_exec",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          osx: {
            known_failures: []
          },
          linux: {
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
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          osx: {
            known_failures: [
              "[-] FAILED: should read the binary data we just wrote"
            ]
          },
          linux: {
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
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          osx: {
            known_failures: [
              "[-] FAILED: should return a list of processes"
            ]
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
        platforms: [:linux, :osx, :windows],
        skipped: false,
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
        name: "test/railgun_reverse_lookups",
        platforms: [:linux, :osx, :windows],
        skipped: false,
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
          :windows
        ],
        skipped: false,
        lines: {
          windows: {
            known_failures: [
              [
                [
                  "[-] [should read values with a 64-bit view] FAILED: should read values with a 64-bit view",
                  "[-] [should read values with a 64-bit view] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should return normalized values] FAILED: should return normalized values",
                  "[-] [should return normalized values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should enumerate keys and values] FAILED: should enumerate keys and values",
                  "[-] [should enumerate keys and values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should create keys] FAILED: should create keys",
                  "[-] [should create keys] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should write REG_BINARY values] FAILED: should write REG_BINARY values",
                  "[-] [should write REG_BINARY values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should write REG_DWORD values] FAILED: should write REG_DWORD values",
                  "[-] [should write REG_DWORD values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should write REG_EXPAND_SZ values] FAILED: should write REG_EXPAND_SZ values",
                  "[-] [should write REG_EXPAND_SZ values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should write REG_MULTI_SZ values] FAILED: should write REG_MULTI_SZ values",
                  "[-] [should write REG_MULTI_SZ values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should write REG_QWORD values] FAILED: should write REG_QWORD values",
                  "[-] [should write REG_QWORD values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should write REG_SZ values] FAILED: should write REG_SZ values",
                  "[-] [should write REG_SZ values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should delete keys] FAILED: should delete keys",
                  "[-] [should delete keys] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should create unicode keys] FAILED: should create unicode keys",
                  "[-] [should create unicode keys] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should write REG_SZ unicode values] FAILED: should write REG_SZ unicode values",
                  "[-] [should write REG_SZ unicode values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should delete unicode keys] FAILED: should delete unicode keys",
                  "[-] [should delete unicode keys] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host."
                ],
                {
                  if: [
                    :meterpreter_runtime_version,
                    :==,
                    "php5.3"
                  ]
                }
              ],
              [
                "[-] FAILED: should write REG_EXPAND_SZ values",
                {
                  if: [
                    [
                      :meterpreter_runtime_version,
                      :==,
                      "php8.2"
                    ],
                    :or,
                    [
                      :meterpreter_runtime_version,
                      :==,
                      "php7.4"
                    ]
                  ]
                }
              ]
            ]
          },
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          }
        }
      },
      {
        name: "test/search",
        platforms: [:linux, :osx, :windows],
        skipped: false,
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
      }
    ]
  }
end
