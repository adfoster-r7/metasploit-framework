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
          global: {
          },
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
            acceptable_failures: []
          },
          windows: {
            required: [],
            acceptable_failures: [
              'Post failed: Rex::Post::Meterpreter::RequestError stdapi_fs_chdir: Operation failed: 1',
              'Call stack:',
              'rex/post/meterpreter/extensions/stdapi/fs/dir.rb',
              'msf/core/post/file.rb',
              'test/modules/post/test/file.rb'
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
        platforms: [
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
              'FAILED: Should retrieve the win32k file version',
              'Exception: Rex::NotImplementedError : The requested method is not implemented',
              'FAILED: Should include error information in the results',
              'FAILED: Should support functions with no parameters',
              'FAILED: Should support functions with literal parameters',
              'FAILED: Should support functions with in/out/inout parameter types',
              'FAILED: Should support calling multiple functions at once',
              'FAILED: Should support writing memory',
              'FAILED: Should support reading memory'
            ]
          },
          linux: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: [
              'FAILED: Should retrieve the win32k file version',
              'Exception: Rex::NotImplementedError : The requested method is not implemented',
              'FAILED: Should include error information in the results',
              'FAILED: Should support functions with no parameters',
              'FAILED: Should support functions with literal parameters',
              'FAILED: Should support functions with in/out/inout parameter types',
              'FAILED: Should support calling multiple functions at once',
              'FAILED: Should support writing memory',
              'FAILED: Should support reading memory'
            ]
          },
          windows: {
            required: [
              'Failed: 0'
            ],
            acceptable_failures: [
              'stdapi_fs_file_expand_path: Operation failed: 1',
              'FAILED: Should retrieve the win32k file version',
              'Exception: Rex::NotImplementedError : The requested method is not implemented',
              'FAILED: Should include error information in the results',
              'FAILED: Should support functions with no parameters',
              'FAILED: Should support functions with literal parameters',
              'FAILED: Should support functions with in/out/inout parameter types',
              'FAILED: Should support calling multiple functions at once',
              'FAILED: Should support writing memory',
              'FAILED: Should support reading memory'
            ]
          }
        }
      },
      {
        name: 'test/railgun_reverse_lookups',
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
            ]
          },
          osx: {
            required: [],
            acceptable_failures: [
              'FAILED: should return a constant name given a const and a filter',
              'FAILED: should return an error string given an error code',
              'Failed: 2'
            ]
          },
          linux: {
            required: [],
            acceptable_failures: [
              'FAILED: should return a constant name given a const and a filter',
              'FAILED: should return an error string given an error code',
              'Failed: 2'
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
              'Failed: 10'
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
            acceptable_failures: [
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
              'FAILED: should raise a runtime exception if services doesnt exist'
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
    ],
  }
end
