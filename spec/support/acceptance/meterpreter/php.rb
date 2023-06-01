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
              "[-] FAILED: should start W32Time",
              "[-] Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)",
              "[-] FAILED: should stop W32Time",
              "[-] FAILED: should modify config on a given service",
              "[-] FAILED: should return status on a given service winmgmt",
              "[-] FAILED: should list services",
              "[-] Could not retrieve the start type of the winmgmt service!",
              "[-] FAILED: should return info on a given service  winmgmt",
              "[-] FAILED: should restart a started service W32Time",
              "[-] FAILED: should start a disabled service",
              "[-] FAILED: should create a service  testes",
              "[-] Could not retrieve the start type of the testes service!",
              "[-] FAILED: should return info on the newly-created service testes",
              "[-] FAILED: should delete the new service testes",
              "[-] FAILED: should raise a runtime exception if services doesnt exist",
              "[-] FAILED: should raise a runtime exception if no access to service"
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
              "[-] FAILED: should create keys",
              "[-] FAILED: should write REG_BINARY values",
              "[-] FAILED: should write REG_DWORD values",
              "[-] FAILED: should write REG_EXPAND_SZ values",
              "[-] FAILED: should write REG_MULTI_SZ values",
              "[-] FAILED: should write REG_QWORD values",
              "[-] FAILED: should write REG_SZ values",
              "[-] FAILED: should delete keys",
              "[-] FAILED: should create unicode keys",
              "[-] FAILED: should write REG_SZ unicode values",
              "[-] FAILED: should delete unicode keys",
              "[-] FAILED: should evaluate key existence",
              "[-] FAILED: should read values",
              "[-] Exception: NoMethodError : undefined method `[]' for nil:NilClass",
              "[-] FAILED: should read values with a 32-bit view",
              "[-] FAILED: should read values with a 64-bit view",
              "[-] FAILED: should return normalized values",
              "[-] FAILED: should enumerate keys and values"
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
