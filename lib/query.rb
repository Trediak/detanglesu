def query_by_options(parser_obj, options = {})
  # Validate options.  If options are input as strings, convert them to arrays via
  # validate_and_transform method
  (users = validate_and_transform(options[:users], "User")) if options[:users]
  (hosts = validate_and_transform(options[:hosts], "Host")) if options[:hosts]
  (runas = validate_and_transform(options[:runas], "Runas")) if options[:runas]
  (flags = validate_and_transform(options[:flags], "Flag")) if options[:flags]
  (commands = validate_and_transform(options[:commands], "Command")) if options[:commands]

  # Fill up access hash with all access for each user
  access = parser_obj.access

  # If options[:users] is set, delete keys that don't match options[:users]
  access.keep_if {|user_key| users.any? {|user| user_key == user}} if users

  # Iterate through each user in access array
  access.each do |k,user_access|
    # Iterate through each chunk of access keeping matches for applicable options
    user_access.keep_if {|chunk| hosts.any? {|host| parser_obj.get_lookup_key(host) == chunk[0]}} if hosts
    user_access.keep_if {|chunk| runas.any? {|ra| parser_obj.get_lookup_key(ra) == chunk[1]}} if runas
    user_access.keep_if {|chunk| flags.any? {|flag| parser_obj.get_flag_number(flag) == chunk[2]}} if flags
    user_access.keep_if {|chunk| commands.any? {|command| parser_obj.get_lookup_key(command) == chunk[3]}} if commands
  end

  # There is the chance of left over users with nothing left after deletes.  Get rid of them.
  access.delete_if {|user_key| access[user_key].empty?}

  return access
end

def validate_and_transform(input, input_type)
  if input.kind_of?(Array) || input.kind_of?(String)
    transformed = input.kind_of?(String) ? input.split(/(?<!\\),/) : input
  else
    abort("Error: #{input_type} input must be array or string")
  end

  return transformed
end