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
        platforms: [:windows],
        skipped: false,
        flaky: false,
        lines: {
          windows: {
            known_failures: [
              "[-] [should start W32Time] FAILED: should start W32Time",
              "[-] [should start W32Time] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should stop W32Time] FAILED: should stop W32Time",
              "[-] [should stop W32Time] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should list services] FAILED: should list services",
              "[-] [should return info on a given service  winmgmt] FAILED: should return info on a given service  winmgmt",
              "[-] [should create a service  testes] FAILED: should create a service  testes",
              "[-] [should create a service  testes] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should return info on the newly-created service testes] FAILED: should return info on the newly-created service testes",
              "[-] [should delete the new service testes] FAILED: should delete the new service testes",
              "[-] [should delete the new service testes] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] [should return status on a given service winmgmt] FAILED: should return status on a given service winmgmt",
              "[-] [should return status on a given service winmgmt] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
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
              [
                [
                  "[-] [should list services] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should return info on a given service  winmgmt] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should return info on the newly-created service testes] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host."
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
                [
                  "[-] [should list services] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should return info on a given service  winmgmt] Exception: Rex::TimeoutError : Send timed out",
                  "[-] [should return info on the newly-created service testes] Exception: Rex::TimeoutError : Send timed out"
                ],
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
            known_failures: [
              "[-] FAILED: should return the stderr output"
            ]
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
              "[-] Post failed: Rex::Post::Meterpreter::RequestError stdapi_fs_chdir: Operation failed: 1",
              "[-] Call stack:",
              "metasploit-framework/lib/rex/post/meterpreter/extensions/stdapi/fs/dir.rb:189:in `chdir'",
              "metasploit-framework/lib/msf/core/post/file.rb:50:in `cd'",
              "metasploit-framework/test/modules/post/test/file.rb:45:in `setup'"
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
              [
                [
                  "[-] [should read values] FAILED: should read values",
                  "[-] [should read values] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
                  "[-] [should read values with a 32-bit view] FAILED: should read values with a 32-bit view",
                  "[-] [should read values with a 32-bit view] Exception: Errno::ECONNRESET : An existing connection was forcibly closed by the remote host.",
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
