module Acceptance::Meterpreter
  PHP_METERPRETER = {
    payloads: [
      {
        name: 'php/meterpreter_reverse_tcp',
        extension: '.php',
        platforms: %i[osx linux windows],
        execute_cmd: ['php', '${payload_path}'],
        generate_options: {
          '-f': 'raw'
        },
        datastore: {
          global: {},
          module: {
            MeterpreterDebugBuild: true
          }
        }
      },
    ],
    module_tests: [
      {
        name: 'test/cmd_exec',
        platforms: %i[
          osx
          linux
          windows
        ],
        lines: {
          all: {
            required: [

            ],
            acceptable_failures: []
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
            acceptable_failures: []
          },
          windows: {
            required: [],
            acceptable_failures: [
              'FAILED: should return the stderr output',
              '; Failed: 1'
            ]
          }
        }
      },
      {
        name: 'test/extapi',
        platforms: %i[
          osx
          linux
          windows
        ],
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
        platforms: %i[
          osx
          linux
          windows
        ],
        # skip: true,
        lines: {
          all: {
            required: [
            ],
            acceptable_failures: []
          },
          osx: {
            required: [],
            acceptable_failures: [
              'FAILED: should read the binary data we just wrote',
              '; Failed: 1'
            ]
          },
          linux: {
            required: [],
            acceptable_failures: [
              'FAILED: should read the binary data we just wrote',
              '; Failed: 1',
            ]
          },
          windows: {
            required: [],
            acceptable_failures: [
              'FAILED: should test for file existence',
              'FAILED: should delete a symbolic link target',
              'Exception: Rex::Post::Meterpreter::RequestError : stdapi_sys_process_execute: Operation failed: Python exception: FileNotFoundError',
              'FAILED: should not recurse into symbolic link directories',
              'Post failed: Rex::Post::Meterpreter::RequestError stdapi_fs_chdir: Operation failed: 1',
              'Call stack:',
              'rex/post/meterpreter/extensions/stdapi/fs/dir.rb',
              'msf/core/post/file.rb',
              'test/modules/post/test/file.rb',
              '; Failed: 3'
            ]
          }
        }
      },
      {
        name: 'test/get_env',
        platforms: %i[
          osx
          linux
          windows
        ],
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
        platforms: %i[
          osx
          linux
          windows
        ],
        # skip: true,
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
              'FAILED: should return a list of processes',
              'Failed: 1'
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
        platforms: [
          :windows
        ],
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
              'FAILED: should write REG_SZ values',
              'FAILED: should write REG_BINARY values',
              'FAILED: should write REG_EXPAND_SZ values',
              'FAILED: should write REG_MULTI_SZ values',
              'FAILED: should write REG_QWORD values',
              'FAILED: should write REG_DWORD values',
              'FAILED: should delete keys',
              'FAILED: should create unicode keys',
              'FAILED: should write REG_SZ unicode values',
              'FAILED: should delete unicode keys',
              'FAILED: should evaluate key existence',
              'PENDING: should evaluate value existence',
              'FAILED: should read values',
              'Exception: NoMethodError : undefined method',
              'FAILED: should return normalized values',
              'FAILED: should enumerate keys and values',
              'Failed: 17'
            ]
          }
        }
      },
      {
        name: 'test/search',
        platforms: %i[
          osx
          linux
          windows
        ],
        lines: {
          all: {
            required: [
              'Failed: 0'
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
            acceptable_failures: []
          }
        }
      },
      {
        name: 'test/services',
        platforms: [
          :windows
        ],
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
            required: [
              'Passed:'
            ],
            acceptable_failures: [
              'Exception: Rex::Post::Meterpreter::ExtensionLoadError : The "extapi" extension is not supported by this Meterpreter type',
              'Exception: Rex::NotImplementedError : The requested method is not implemented.',
              'Exception: Rex::NotImplementedError : Unsupported architecture (must be ARCH_X86 or ARCH_X64)',
              'FAILED: should write REG_BINARY values',
              'FAILED: should write REG_EXPAND_SZ values',
              'FAILED: should write REG_MULTI_SZ values',
              'FAILED: should write REG_QWORD values',
              'FAILED: should start W32Time',
              'FAILED: should stop W32Time',
              'FAILED: should list services',
              'FAILED: should return info on a given service',
              'FAILED: should create a service',
              'FAILED: should return info on the newly-created service',
              'FAILED: should delete the new service testes',
              'FAILED: should return status on a given service',
              'Could not retrieve the start type of the winmgmt service!',
              'Could not retrieve the start type of the testes service!',
              'FAILED: should modify config on a given service',
              'FAILED: should start a disabled service',
              'FAILED: should restart a started service',
              'FAILED: should raise a runtime exception if no access to service',
              'FAILED: should raise a runtime exception if services doesnt exist',
              '; Failed: 13'
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
