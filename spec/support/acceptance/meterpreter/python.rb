module Acceptance::Meterpreter
  PYTHON_METERPRETER = {
    payloads: [
      {
        name: 'python/meterpreter_reverse_tcp',
        extension: '.py',
        platforms: %i[osx linux windows],
        execute_cmd: ['python', '${payload_path}'],
        generate_options: {
          '-f': 'raw'
        },
        datastore: {
          global: {},
          module: {
            MeterpreterTryToFork: false,
            PythonMeterpreterDebug: true
          }
        }
      },
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
              ['should return the result of echo', { flaky: true }],
              ['should return the result of echo with double quotes', { flaky: true }],
              ['; Failed:', { flaky: true }],
            ]
          },
          linux: {
            required: [],
            acceptable_failures: [
              ['should return the stderr output', { flaky: true }],
              ['should return the result of echo', { flaky: true }],
              ['should return the result of echo with double quotes', { flaky: true }],
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
          },
          windows: {
            required: [

            ],
            acceptable_failures: [
              # Python Meterpreter occasionally fails to verify that files exist
              ['FAILED: should test for file existence', { flaky: true }],
              'Post failed: Errno::ENOENT No such file or directory @ rb_sysopen - /bin/echo',
              'Call stack:',
              'test/modules/post/test/file.rb',
              'test/lib/module_test.rb',
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
      {
        name: 'test/meterpreter',
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
              '; Failed: '
            ],
            acceptable_failures: [
              [
                [
                  'FAILED: should return network interfaces',
                  'stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError',
                  'FAILED: should have an interface that matches session_host',
                  'stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError',
                  'stdapi_net_config_get_routes: Operation failed: Python exception: TypeError'
                ],
                { if: ENV['METERPRETER_RUNTIME_VERSION'] == '3.6' }
              ],

              # TODO: Python OSX Meterpreter chokes on netstat -rn output:
              #   '172.16.83.3        0.c.29.a1.cb.67    UHLWIi     bridge1    358'
              #  Exception:
              #   'gateway': inet_pton(state, gateway),
              #   *** error: illegal IP address string passed to inet_pton
              [
                [
                  'FAILED: should return network routes',
                  'stdapi_net_config_get_routes: Operation failed: Unknown error',
                ],
                { if: ENV['METERPRETER_RUNTIME_VERSION'] == '3.6' || !ENV['CI'] }
              ],
              [
                [
                  'FAILED: should return network interfaces',
                  'stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError',
                  'FAILED: should have an interface that matches session_host',
                  'stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError',
                  'FAILED: should return network routes',
                  'stdapi_net_config_get_routes: Operation failed: Python exception: TypeError',
                ],
                { if: ENV['METERPRETER_RUNTIME_VERSION'] == '3.8' }
              ]
            ]
          },
          linux: {
            required: [],
            acceptable_failures: []
          },
          windows: {
            required: [],
            acceptable_failures: [
              # https://github.com/rapid7/metasploit-framework/pull/16178
              [
                [
                  'FAILED: should return the proper directory separator',
                  '; Failed: 1',
                ],
                { flaky: true }
              ]
            ]
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
            ],
            acceptable_failures: [
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
              'Failed: 0'
            ],
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
              'Failed: 0'
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
              'Failed: 0'
            ],
            acceptable_failures: [
              'FAILED: should start W32Time',
              'FAILED: should stop W32Time',
              'FAILED: should list services',
              'Exception: RuntimeError : Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error',
              "Exception: NoMethodError : undefined method `include?' for true:TrueClass",
              'FAILED: should raise a runtime exception if no access to service',
              'The "extapi" extension is not supported by this Meterpreter type',
              'FAILED: should return info on a given service',
              'FAILED: should create a service',
              'FAILED: should return info on the newly-created service',
              'FAILED: should raise a runtime exception if services doesnt exist',
              'FAILED: should delete the new service',
              'FAILED: should return status on a given service',
              'FAILED: should modify config on a given service',
              'FAILED: should start a disabled service',
              'FAILED: should restart a started service',
              "Exception: NoMethodError : undefined method `service' for nil:NilClass",
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
