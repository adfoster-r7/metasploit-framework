# -*- coding: binary -*-

module Rex
  module Post
    module FTP
      module Ui
        ###
        #
        # FTP Client commands for file operations
        #
        ###
        class Console::CommandDispatcher::Client

          include Rex::Post::FTP::Ui::Console::CommandDispatcher

          @@ls_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu']
          )

          @@cd_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu']
          )

          @@get_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu']
          )

          @@put_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu']
          )

          @@cat_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [false, 'Help menu']
          )

          #
          # List of supported commands.
          #
          def commands
            {
              'ls' => 'List files in the current remote directory',
              'dir' => 'List files in the current remote directory (alias for ls)',
              'pwd' => 'Print the current remote working directory',
              'cd' => 'Change the current remote working directory',
              'get' => 'Download a file from the remote server',
              'download' => 'Download a file from the remote server (alias for get)',
              'put' => 'Upload a file to the remote server',
              'upload' => 'Upload a file to the remote server (alias for put)',
              'cat' => 'Read and display a remote file'
            }
          end

          #
          # FTP Client
          #
          def name
            'FTP Client'
          end

          #
          # Display the contents of the current remote directory
          #
          def cmd_ls(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_ls_help
              return
            end

            path = args[0]
            begin
              listing = client.list(path)
              print_line(listing.to_s)
            rescue Rex::Proto::FTP::Error => e
              print_error("Failed to list directory: #{e.message}")
            end
          end

          def cmd_ls_help
            print_line 'Usage: ls [path]'
            print_line
            print_line 'List files in the remote directory.'
            print_line @@ls_opts.usage
          end

          alias cmd_dir cmd_ls
          alias cmd_dir_help cmd_ls_help

          #
          # Print the current working directory
          #
          def cmd_pwd(*args)
            if args.include?('-h') || args.include?('--help')
              print_line 'Usage: pwd'
              print_line
              print_line 'Print the current remote working directory.'
              return
            end

            begin
              dir = client.pwd
              print_line(dir)
            rescue Rex::Proto::FTP::Error => e
              print_error("Failed to get working directory: #{e.message}")
            end
          end

          #
          # Change directory
          #
          def cmd_cd(*args)
            if args.include?('-h') || args.include?('--help') || args.length != 1
              cmd_cd_help
              return
            end

            begin
              client.cwd(args[0])
              print_good("Changed directory to #{args[0]}")
            rescue Rex::Proto::FTP::Error => e
              print_error("Failed to change directory: #{e.message}")
            end
          end

          def cmd_cd_help
            print_line 'Usage: cd <path>'
            print_line
            print_line 'Change the current remote working directory.'
            print_line @@cd_opts.usage
          end

          #
          # Download a file
          #
          def cmd_get(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_get_help
              return
            end

            remote_path = nil
            local_path = nil

            @@get_opts.parse(args) do |_opt, idx, val|
              case idx
              when 0
                remote_path = val
              when 1
                local_path = val
              end
            end

            if remote_path.blank?
              print_error('No remote path given')
              return
            end

            local_path = ::File.basename(remote_path) if local_path.nil?

            begin
              data = client.get(remote_path)
              ::File.binwrite(local_path, data)
              print_good("Downloaded #{remote_path} to #{local_path} (#{data.length} bytes)")
            rescue Rex::Proto::FTP::Error => e
              print_error("Failed to download file: #{e.message}")
            end
          end

          def cmd_get_help
            print_line 'Usage: get <remote_path> [local_path]'
            print_line
            print_line 'Download a file from the remote server.'
            print_line @@get_opts.usage
          end

          #
          # Upload a file
          #
          def cmd_put(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_put_help
              return
            end

            local_path = nil
            remote_path = nil

            @@put_opts.parse(args) do |_opt, idx, val|
              case idx
              when 0
                local_path = val
              when 1
                remote_path = val
              end
            end

            if local_path.blank?
              print_error('No local path given')
              return
            end

            unless ::File.exist?(local_path)
              print_error("Local file not found: #{local_path}")
              return
            end

            remote_path = ::File.basename(local_path) if remote_path.nil?

            begin
              data = ::File.binread(local_path)
              client.put(remote_path, data)
              print_good("Uploaded #{local_path} to #{remote_path} (#{data.length} bytes)")
            rescue Rex::Proto::FTP::Error => e
              print_error("Failed to upload file: #{e.message}")
            end
          end

          def cmd_put_help
            print_line 'Usage: put <local_path> [remote_path]'
            print_line
            print_line 'Upload a file to the remote server.'
            print_line @@put_opts.usage
          end

          alias cmd_download cmd_get
          alias cmd_download_help cmd_get_help

          alias cmd_upload cmd_put
          alias cmd_upload_help cmd_put_help

          #
          # Read and display a remote file
          #
          def cmd_cat(*args)
            if args.include?('-h') || args.include?('--help') || args.length != 1
              cmd_cat_help
              return
            end

            begin
              data = client.read_file(args[0])
              print_line(data.to_s)
            rescue Rex::Proto::FTP::Error => e
              print_error("Failed to read file: #{e.message}")
            end
          end

          def cmd_cat_help
            print_line 'Usage: cat <remote_path>'
            print_line
            print_line 'Read and display a remote file.'
            print_line @@cat_opts.usage
          end

        end
      end
    end
  end
end
