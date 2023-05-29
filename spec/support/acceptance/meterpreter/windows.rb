module Acceptance::Meterpreter
  WINDOWS_METERPRETER = {
    payloads: [
      {
        name: 'windows/meterpreter/reverse_tcp',
        extension: '.exe',
        platforms: [:windows],
        execute_cmd: ['${payload_path}'],
        executable: true,
        generate_options: {
          '-f': 'exe'
        },
        datastore: {
          global: {},
          module: {
            MeterpreterTryToFork: false,
            MeterpreterDebugBuild: true
          }
        }
      },
    ],
    module_tests: [
      {
        name: 'test/cmd_exec',
        platforms: [:windows],
        lines: {
          all: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: [
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
          windows: {
            required: [],
            acceptable_failures: []
          }
        }
      },
      {
        name: 'test/file',
        platforms: [:windows],
        lines: {
          all: {
            required: [

            ],
            acceptable_failures: [
              # 'Call stack:',
              # 'test/modules/post/test/file.rb',
              # 'test/lib/module_test.rb',
            ]
          },
          windows: {
            required: [],
            acceptable_failures: [
            ]
          }
        }
      },
      {
        name: 'test/get_env',
        platforms: [:windows],
        lines: {
          all: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: []
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
      {
        name: 'test/meterpreter',
        platforms: [:windows],
        lines: {
          all: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: []
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
      {
        name: 'test/railgun',
        platforms: [:windows],
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: [
            ]
          },
          windows: {
            required: [
              'Failed: 0'
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
          windows: {
            required: [
              'Failed: 0'
            ],
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
            acceptable_failures: []
          },
          windows: {
            required: [],
            acceptable_failures: [
            ]
          }
        }
      },
      {
        name: 'test/search',
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
            acceptable_failures: []
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
            acceptable_failures: [
              'FAILED: should start W32Time',
              ['Exception: TypeError : exception class/object expected', { flaky: true }],
              'FAILED: should stop W32Time',
              'FAILED: should list services',
              'Exception: RuntimeError : Unable to open service manager: FormatMessage failed to retrieve the error',
              'Exception: RuntimeError : Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error',
              'Request Error extapi_service_query: Operation failed: 1060 falling back to registry technique',
              'The "extapi" extension is not supported by this Meterpreter type',
              'FAILED: should return info on a given service',
              'FAILED: should create a service',
              'FAILED: should return info on the newly-created service',
              'FAILED: should delete the new service',
              'FAILED: should return status on a given service',
              'FAILED: should modify config on a given service',
              'FAILED: should start a disabled service',
              'FAILED: should restart a started service'
            ]
          }
        }
      },
    ]
  }
end
