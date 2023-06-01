require 'support/acceptance/meterpreter'

module Acceptance::Meterpreter
  METTLE_METERPRETER = {
    payloads: [
      {
        name: "linux/x64/meterpreter/reverse_tcp",
        extension: "",
        platforms: [:linux],
        executable: true,
        execute_cmd: ["${payload_path}"],
        generate_options: {
          '-f': "elf"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterTryToFork: false,
            MeterpreterDebugBuild: true
          }
        }
      },
      {
        name: "osx/x64/meterpreter_reverse_tcp",
        extension: "",
        platforms: [:osx],
        executable: true,
        execute_cmd: ["${payload_path}"],
        generate_options: {
          '-f': "macho"
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
        name: "test/search",
        platforms: [
          :linux,
          [
            :osx,
            {
              skip: true,
              reason: "skipped - test/search hangs in osx and CPU spikes to >300%"
            }
          ]
        ],
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
      },
      {
        name: "test/cmd_exec",
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
      },
      {
        name: "test/extapi",
        platforms: [:osx, :linux],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: []
          },
          linux: {
            known_failures: [
              "[-] Post failed: RuntimeError x86_64-linux-musl/extapi not found",
              "[-] Call stack:",
              "metasploit-framework/vendor/bundle/ruby/3.0.0/gems/metasploit_payloads-mettle-1.0.20/lib/metasploit_payloads/mettle.rb:205:in `load_extension'",
              "metasploit-framework/lib/rex/post/meterpreter/client_core.rb:356:in `use'",
              "metasploit-framework/test/modules/post/test/extapi.rb:32:in `setup'"
            ]
          }
        }
      },
      {
        name: "test/file",
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
      },
      {
        name: "test/get_env",
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
      },
      {
        name: "test/meterpreter",
        platforms: [:osx, :linux],
        skipped: false,
        flaky: false,
        lines: {
          osx: {
            known_failures: [
              "[-] FAILED: should return network interfaces",
              "[-] FAILED: should have an interface that matches session_host"
            ]
          },
          linux: {
            known_failures: []
          }
        }
      },
      {
        name: "test/railgun_reverse_lookups",
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
