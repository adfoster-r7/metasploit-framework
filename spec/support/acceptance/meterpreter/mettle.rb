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
        name: "test/cmd_exec",
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Payload not compiled for platform"
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
      },
      {
        name: "test/extapi",
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Payload not compiled for platform"
            }
          ]
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: [
              "[-] Post failed: RuntimeError x86_64-linux-musl/extapi not found",
              "[-] Call stack:",
              "metasploit-framework/vendor/bundle/ruby/3.0.0/gems/metasploit_payloads-mettle-1.0.20/lib/metasploit_payloads/mettle.rb:205:in `load_extension'",
              "metasploit-framework/lib/rex/post/meterpreter/client_core.rb:356:in `use'",
              "metasploit-framework/test/modules/post/test/extapi.rb:32:in `setup'"
            ]
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
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Payload not compiled for platform"
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
      },
      {
        name: "test/get_env",
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Payload not compiled for platform"
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
      },
      {
        name: "test/meterpreter",
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Payload not compiled for platform"
            }
          ]
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: [
              "[-] FAILED: should return network interfaces",
              "[-] FAILED: should have an interface that matches session_host"
            ]
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/railgun",
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Payload not compiled for platform"
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
      },
      {
        name: "test/railgun_reverse_lookups",
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Payload not compiled for platform"
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
        name: "test/search",
        platforms: [
          :linux,
          [
            :osx,
            {
              skip: true,
              reason: "skipped - test/search hangs in osx and CPU spikes to >300%"
            }
          ],
          [
            :windows,
            {
              skip: true,
              reason: "Payload not compiled for platform"
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
