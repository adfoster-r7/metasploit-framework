module Acceptance::Meterpreter
  JAVA_METERPRETER = {
    payloads: [
      {
        name: 'java/meterpreter/reverse_tcp',
        extension: '.jar',
        platforms: %i[osx linux windows],
        execute_cmd: ['java', '-jar', '${payload_path}'],
        generate_options: {
          '-f': 'jar'
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
        name: 'test/cmd_exec',
        platforms: %i[osx linux windows],
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
        name: 'test/extapi',
        platforms: %i[osx linux windows],
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: [
              'The "extapi" extension is not supported by this Meterpreter type',
              'Call stack:',
              'test/modules/post/test/extapi.rb'
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
      {
        name: 'test/file',
        platforms: %i[osx linux windows],
        lines: {
          all: {
            required: [

            ],
            acceptable_failures: []
          },
          osx: {
            required: [
              'Passed: '
            ],
            acceptable_failures: []
          },
          linux: {
            required: [
              'Passed: '
            ],
            acceptable_failures: [
              # Consistently fails on CI
              ["Didn't read what we wrote, actual file on target: ||", { if: ENV['CI'] }],
              # Occasionally fails
              ['FAILED: should append binary data', { flaky: true }],
              ['FAILED: should upload a file', { flaky: true }],
              ['; Failed:', { flaky: true }],
              ['Exception: EOFError : EOFError', { flaky: true }]
            ]
          },
          windows: {
            required: [],
            acceptable_failures: [
              ['FAILED: should upload a file', { flaky: true }],
              ['; Failed:', { flaky: true }],
              ['Exception: EOFError : EOFError', { flaky: true }],
              'Post failed: Errno::ENOENT No such file or directory @ rb_sysopen - /bin/echo',
              'Call stack:',
              'modules/post/test/file.rb',
              'lib/module_test.rb',
              'failed to create the symbolic link'
            ]
          }
        }
      },
      {
        name: 'test/get_env',
        platforms: %i[osx linux windows],
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
        platforms: %i[osx linux windows],
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
        platforms: %i[osx linux windows],
        # Railgun is not supported on this platform
        skip: true
      },
      {
        name: 'test/railgun_reverse_lookups',
        platforms: %i[osx linux windows],
        # Railgun is not supported on this platform
        skip: true
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
              'FAILED: should create keys',
              'FAILED: should write REG_BINARY values',
              'FAILED: should write REG_SZ values',
              'FAILED: should write REG_EXPAND_SZ values',
              'FAILED: should write REG_MULTI_SZ values',
              'FAILED: should write REG_DWORD values',
              'FAILED: should delete keys',
              'FAILED: should create unicode keys',
              'FAILED: should write REG_QWORD values',
              'FAILED: should write REG_SZ unicode values',
              'FAILED: should delete unicode keys',
              'FAILED: should evaluate key existence',
              'PENDING: should evaluate value existence',
              'FAILED: should read values',
              'Exception: NoMethodError : undefined method',
              'FAILED: should return normalized values',
              'FAILED: should enumerate keys and values',
              'Passed: 3; Failed: 14'
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
              'Failed: 0'
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
        # focus: true,
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: []
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
            acceptable_failures: [
              'stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type',
              'Exception: Rex::Post::Meterpreter::ExtensionLoadError : The "extapi" extension is not supported by this Meterpreter type',
              'Exception: Rex::NotImplementedError : The requested method is not implemented.',
              'FAILED: should start W32Time',
              'FAILED: should stop W32Time',
              'FAILED: should list services',
              'FAILED: should return info on a given service',
              'FAILED: should create a service',
              'FAILED: should return info on the newly-created service',
              'FAILED: should delete the new service testes',
              'FAILED: should return status on a given service',
              'FAILED: should modify config on a given service',
              'FAILED: should start a disabled service',
              'FAILED: should restart a started service',
              'FAILED: should raise a runtime exception if no access to service',
              'FAILED: should raise a runtime exception if services doesnt exist',
              'Could not retrieve the start type of the winmgmt service!',
              'Could not retrieve the start type of the testes service!',
              'Failed: 3'
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
    ]
  }
end
