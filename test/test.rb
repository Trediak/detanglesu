require_relative "../detanglesu"

parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
puts parser.lookup_table.inspect

describe "Parser" do
  commands = []

  parser.access['user_aaaa'].each do |access|
    commands << access[-1]
  end
  it "should be able to handle escaped commas" do
    expect(commands).to include(parser.get_lookup_key('/usr/bin/command13 \, "comma escape test"'))
  end

  it "should be able to handle escaped backslashes" do
    expect(commands).to include(parser.get_lookup_key('/usr/bin/command11 \\\\ "backslash escape test"'))
  end
end

describe "User Access" do
  hosts = []

  parser.access['user_aaaa'].each do |access|
    hosts << access[0]
  end

  it 'user_aaaa should be able to run commands on host_00002' do
    expect(hosts).to include(parser.get_lookup_key('host_00002'))
  end
end
