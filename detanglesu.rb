module DetangleSu
  class Parser
    def initialize(params = {})
      @filepath         = params.fetch(:filepath, './')
      @filename         = params.fetch(:filename, 'sudoers')
      @alias            = { user: {}, runas: {}, host: {}, cmnd: {} }
      @lookup_table     = {}
      @access           = {}
      @temp_user_specs  = []
      @unique_id        = 0

      # Parse and process the sudoers file
      parse_file
      process_user_specs
    end

    def access
      access = @access
    end

    def lookup_table
      lookup_table = @lookup_table
    end

    def parse_file
      File.open(File.join(@filepath, @filename), 'r') do |file|
        file.each_line do |line|
          case line
          when /^Defaults/
            # hold defaults in case rewriting sudoers file
            # not currently used.  add later
          when /^(User|Runas|Host|Cmnd)_Alias/
            process_alias(file, line)
          when /^\s*#/
            # drop comments
          when /^\s*$/
            # drop blank lines
          else
            # hold user specifications temporarily until file completely read
            preprocess_user_specs(file, line)
          end
        end
      end
    end

    def process_alias(file, line)
      add_to_lookup_table("root")

      # separate left from right for processing
      split_array = line.rstrip!.split('=', 2)

      # add additional lines in case of continuation
      while (line[-1,1].chr == '\\') do
        line = file.readline
        split_array[1]<<line.rstrip!
      end

      # add to correct alias type by performing voodoo string manipulation.
      # step one: remove alias type from left side and collapse spaces.  add leftover value as hash key
      # step two: collapse spaces from right side and remove "\" from continuation
      # right is also assigned to "list" for add_to_lookup_table method
      case split_array[0]
      when /^User_Alias/
        @alias[:user][split_array[0].gsub!(/User_Alias/, '').gsub!(/\s*/,'')] = list =split_array[1].gsub!(/(\s|\\)/i,'')
      when /^Runas_Alias/
        @alias[:runas][split_array[0].gsub!(/Runas_Alias/, '').gsub!(/\s*/,'')] = list = split_array[1].gsub!(/(\s|\\)/i,'')
      when /^Host_Alias/
        @alias[:host][split_array[0].gsub!(/Host_Alias/, '').gsub!(/\s*/,'')] = list = split_array[1].gsub!(/(\s|\\)/i,'')
      when /^Cmnd_Alias/
        @alias[:cmnd][split_array[0].gsub(/Cmnd_Alias/, '').gsub(/\s*/,'')] = list = split_array[1].lstrip.gsub(/\\/,'').gsub(/,\s*/,',')
      end

      add_to_lookup_table(list)
    end

    def preprocess_user_specs(file, line)
      temp_specs = []

      # separate left from right for processing
      split_array = line.rstrip!.split('=', 2)

      # add additional lines in case of continuation
      while (line[-1,1].chr == '\\') do
        line = file.readline
        split_array[1]<<line.rstrip!
      end

      ## process left side
      # collapse spaces around commas for multiple users and/or hosts
      left_side = split_array[0].rstrip.gsub(/,\s*/, ',')

      # collapse spaces between users and hosts and push onto temp_specs
      temp_specs << left_side = left_side.split(/\s+/)

      # Iterate through users and add to @lookup_table if applicable
      left_side[0].split(',').each { |user| add_to_lookup_table(user) unless is_user?(user)}

      # Iterate through hosts and add to @lookup_table if applicable
      left_side[1].split(',').each { |host| add_to_lookup_table(host) unless is_host?(host)} 
      
      ## process right side
      # collapse spaces around commas
      right_temp = split_array[1].rstrip.gsub(/(?<!\\),\s*/, ',')

      # remove leading "\" and whitespace on new command continuation
      right_temp = right_temp.gsub(/\,\s*\\\s*/,',')

      # remove leading "\" and collapse whitespace on same command continuation
      right_temp = right_temp.gsub(/\s*[^\\]\\(?!,)[^\\]\s*/, ' ')

      # remove possible left space and split on ","
      right_side = right_temp.lstrip.split(/(?<!\\),/)
      
      # iterate through right side and split out runas users and flags
      # Note: seriously, the most annoying method I have written in a long time.
      # Too much time was wasted here.  :(
      right_side.each_with_index do |command,index|
        if command =~ /^\s*(\(.+\)|PASSWD:|NOPASSWD:)/
          right_side_cell = []
          temp_command = command.split(' ')
          command.split(' ').each_with_index do |chunk, i|
            if chunk =~ /(\(.+\)|PASSWD:|NOPASSWD:)/
              right_side_cell << chunk
              temp_command.delete_at(0)

              # add runas chunk to @lookup_table if applicable
              if chunk =~ /\(.+\)/
                chunk = chunk.gsub(/[\(\)]/,'')
                add_to_lookup_table(chunk) unless is_runas?(chunk)
              end  
            else
              right_side_cell << temp_command = temp_command.join(' ')

              # add command chunk (temp_command) to @lookup_table if applicable
              add_to_lookup_table(temp_command) unless is_cmnd?(temp_command)
              break
            end
          end
          right_side[index] = right_side_cell
        else
          add_to_lookup_table(command) unless is_cmnd?(command)
        end
      end

      ## complete preprocessing
      # add right_side to temp_specs and flatten array for later processing 
      # and add to @temp_user_specs
      temp_specs << right_side
      temp_specs.flatten!

      @temp_user_specs << temp_specs
    end

    def process_user_specs
      # This method is one giant iteration of iterations to build out access.  Begin by iterating through
      # temp_user_specs nested arrays. Iterate for each user, then iterate by host,
      # and finally iterate through remaining array cells for flags, runas, and commands pushing
      # everything onto @access hash by user.  All information, outside of user name hash keys, is
      # stored via a reference number derived from @lookup_table created via the alias processing
      # and preprocess_user_specs methods.

      @temp_user_specs.each do |spec|
        # run spec[0] (user cell) through expand_users method for any user aliases
        user_list = expand_users(spec[0].split(','))

        # iterate each user in this cell
        user_list.split(',').each do |user|
          
          # run spec[1] (host cell) through expand_hosts method for any user aliases
          host_list = expand_hosts(spec[1].split(','))

          # iterate each host for given user
          host_list.split(',').each do |host|

            # Iterate each remaining cell
            svc_accts = "root"
            commands  = ""
            flag      = 0

            spec[2..spec.length].each do |cell|
              case cell
              when /\(.+\)/
                svc_accts = expand_runas(cell.gsub(/[\(\)]/,''))
                next
              when /^PASSWD:/
                flag = 1
                next
              when /^NOPASSWD:/
                flag = 2
                next
              else
                commands = expand_commands(cell.split(','))
                svc_accts.split(',').each do |account|
                  commands.split(/(?<!\\),/).each do |command|
                    converted_access = [get_lookup_key(host), get_lookup_key(account), flag, get_lookup_key(command)]
                    if @access.has_key?(user)
                      @access[user] << converted_access unless @access[user].include?(converted_access)
                    else
                      @access[user] = [converted_access]
                    end
                  end # end command iteration
                end # end svc_account iteration
              end # end spec cell case statement
            end # end spec iteration
          end # end host iteration
        end # end user iteration
      end # end @temp_user_specs array iteration
    end # end process user specs method

    def get_lookup_value(lookup)
      return @lookup_table[lookup]
    end

    def get_lookup_key(lookup)
      return @lookup_table.key(lookup)
    end

    def get_flag(flag)
      case flag
      when 1
        return "PASSWD:"
      when 2
        return "NOPASSWD:"
      else
        return ""
      end
    end

    def get_flag_number(flag)
      case flag
      when "PASSWD:"
        return 1
      when "NOPASSWD:"
        return 2
      else
        return ""
      end
    end

  private
    def expand_users(user_list)
      full_user_list = []
      user_list.each do |user|
        if @alias[:user].has_key?(user)
          full_user_list << @alias[:user][user]
        else
          full_user_list << user
        end
      end
      return full_user_list.join(',')
    end

    def expand_hosts(host_list)
      full_host_list = []
      host_list.each do |host|
        if @alias[:host].has_key?(host)
          full_host_list << @alias[:host][host]
        else
          full_host_list << host
        end
      end
      return full_host_list.join(',')
    end

    def expand_runas(runas)
      if @alias[:runas].has_key?(runas)
        full_runas_list = @alias[:runas][runas]
      else
        full_runas_list = runas
      end
      return full_runas_list
    end

    def expand_commands(commands_list)
      full_commands_list = []
      commands_list.each do |command|
        if @alias[:cmnd].has_key?(command)
          full_commands_list << @alias[:cmnd][command]
        else
          full_commands_list << command
        end
      end
      return full_commands_list.join(',')
    end

    def is_user?(data)
      return @alias[:user].has_key?(data)
    end

    def is_runas?(data)
      return @alias[:runas].has_key?(data)
    end

    def is_host?(data)
      return @alias[:host].has_key?(data)
    end

    def is_cmnd?(data)
      return @alias[:cmnd].has_key?(data)
    end

    def add_to_lookup_table(list)
      # convert "list" to array for iteration
      #list = list.split(',')
      list = list.split(/(?<!\\),\s*/)

      # iterate through "list" adding to lookup table with a unique integer value if it doesn't exist
      list.each do |item|
        if !@lookup_table.has_value?(item)
          @lookup_table[@unique_id.to_s] = item
          @unique_id += 1
        end
      end
    end
  end
end
