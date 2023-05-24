module Acceptance::Meterpreter
  METTLE_METERPRETER = {
    payloads: [
      {
        name: 'linux/x64/meterpreter/reverse_tcp',
        extension: '',
        platforms: [:linux],
        executable: true,
        execute_cmd: ['${payload_path}'],
        generate_options: {
          '-f': 'elf'
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
        name: 'osx/x64/meterpreter_reverse_tcp',
        extension: '',
        platforms: [:osx],
        executable: true,
        execute_cmd: ['${payload_path}'],
        generate_options: {
          '-f': 'macho'
        },
        datastore: {
          global: {},
          module: {
            MeterpreterTryToFork: false,
            MeterpreterDebugBuild: true
          }
        }
      },
      # {
      #   name: 'osx/x64/meterpreter/reverse_tcp',
      #   extension: '',
      #   platforms: [:osx],
      #   executable: true,
      #   execute_cmd: ['${payload_path}'],
      #   generate_options: {
      #     '-f': 'macho'
      #   },
      #   datastore: {
      #     global: {
      #     },
      #     module: {
      #       MeterpreterTryToFork: false,
      #       MeterpreterDebugBuild: true
      #     }
      #   }
      # }
    ],
    module_tests: [
      {
        name: 'test/cmd_exec',
        platforms: %i[osx linux windows],
        lines: {
          all: {
            required: [
              'Passed: '
            ],
            acceptable_failures: []
          },
          osx: {
            required: [],
            acceptable_failures: [
              ['should return the stderr output', { flaky: true }],
              ['; Failed:', { flaky: true }],
            ]
          },
          linux: {
            required: [],
            acceptable_failures: [
              ['should return the stderr output', { flaky: true }],
              ['; Failed:', { flaky: true }],
            ]
          },
          windows: {
            required: [],
            acceptable_failures: []
          }
        }
      },
      {
        name: 'test/extapi',
        platforms: %i[osx linux windows],
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: [

            ]
          },
          osx: {
            required: [],
            acceptable_failures: [
              'The "extapi" extension is not supported by this Meterpreter type',
              'Call stack:',
              'test/modules/post/test/extapi.rb'
            ]
          },
          linux: {
            required: [],
            acceptable_failures: [
              'Post failed: RuntimeError x86_64-linux-musl/extapi not found',
              'lib/metasploit_payloads/mettle.rb',
              'lib/rex/post/meterpreter/client_core.rb',
              'Call stack:',
              'test/modules/post/test/extapi.rb'
            ]
          }
        }
      },
      {
        name: 'test/file',
        platforms: %i[osx linux],
        lines: {
          all: {
            required: [

            ],
            acceptable_failures: [
            ]
          },
          osx: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: []
          },
          linux: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: [
            ]
          }
        }
      },
      {
        name: 'test/get_env',
        platforms: %i[osx linux],
        lines: {
          all: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: [
            ]
          },
          osx: {
            required: [],
            acceptable_failures: []
          },
          linux: {
            required: [],
            acceptable_failures: []
          }
        }
      },
      {
        name: 'test/meterpreter',
        platforms: %i[osx linux],
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: [
            ]
          },
          osx: {
            required: [
              '; Failed: 2'
            ],
            acceptable_failures:
              [
                'FAILED: should return network interfaces',
                'FAILED: should have an interface that matches session_host',
                '; Failed: 2'
              ]
          },
          linux: {
            required: [],
            acceptable_failures: []
          }
        }
      },
      {
        name: 'test/railgun',
        platforms: [
        ],
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: [
            ]
          },
          osx: {
            required: [
            ],
            acceptable_failures: [
            ]
          },
          linux: {
            required: [
            ],
            acceptable_failures: [
            ]
          }
        }
      },
      {
        name: 'test/railgun_reverse_lookups',
        platforms: %i[osx linux windows],
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: [
            ]
          },
          osx: {
            required: [
              'Passed: 0; Failed: 2'
            ],
            acceptable_failures: [
              'FAILED: should return a constant name given a const and a filter',
              'FAILED: should return an error string given an error code',
              'Passed: 0; Failed: 2'
            ]
          },
          linux: {
            required: [
              'Passed: 0; Failed: 2'
            ],
            acceptable_failures: [
              'FAILED: should return a constant name given a const and a filter',
              'FAILED: should return an error string given an error code',
              'Passed: 0; Failed: 2'
            ]
          },
          windows: {
            required: [],
            acceptable_failures: []
          }
        }
      },
      {
        name: 'test/registry',
        platforms: [:windows],
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: [
            ]
          },
          osx: {
            required: [],
            acceptable_failures: []
          },
          linux: {
            required: [],
            acceptable_failures: []
          },
          windows: {
            required: [
              'Passed: 10; Failed: 1'
            ],
            acceptable_failures: [
            ]
          }
        }
      },
      {
        name: 'test/search',
        platforms: [
          # TODO: Hangs:
          #  :osx,
          :linux,
          :windows
        ],
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: [
            ]
          },
          osx: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: [
            ]
          },
          linux: {
            required: [],
            acceptable_failures: []
          },
          windows: {
            required: [],
            acceptable_failures: []
          }
        }
      },
      {
        name: 'test/services',
        platforms: [:windows],
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: [
            ]
          },
          osx: {
            required: [],
            acceptable_failures: []
          },
          linux: {
            required: [],
            acceptable_failures: []
          },
          windows: {
            required: [
              'Passed: 11; Failed: 2'
            ],
            acceptable_failures: [
              'FAILED: should start W32Time',
              'FAILED: should stop W32Time',
              'FAILED: should list services',
              'Exception: RuntimeError : Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error',
              'The "extapi" extension is not supported by this Meterpreter type',
              'FAILED: should return info on a given service',
              'FAILED: should create a service',
              'FAILED: should return info on the newly-created service',
              'FAILED: should delete the new service',
              'FAILED: should return status on a given service',
              'FAILED: should modify config on a given service',
              'FAILED: should start a disabled service',
              'FAILED: should restart a started service',
              'Passed: 11; Failed: 2'
            ]
          }
        }
      },
      {
        name: 'test/unix',
        platforms: %i[osx linux],
        lines: {
          all: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: [
            ]
          },
          osx: {
            required: [],
            acceptable_failures: []
          },
          linux: {
            required: [],
            acceptable_failures: []
          },
          windows: {
            required: [],
            acceptable_failures: []
          }
        }
      },
    ]
  }
end
