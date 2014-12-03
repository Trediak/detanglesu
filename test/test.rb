require_relative "../detanglesu"
require_relative "../lib/query"

describe 'query_by_options' do
  describe 'query single user "user_llll"' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:users => 'user_llll'})
    it 'should contain key "user_llll"' do
      expect(access).to have_key('user_llll')
    end

    it 'should have a hash count equal to 1' do
      expect(access.count).to eq(1)
    end

    it 'should contain 9 descriptions of access' do
      expect(access['user_llll'].count).to eq(9)
    end
  end
  
  describe 'query multiple users "user_llll" and "user_mmmm"' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:users => 'user_llll,user_mmmm'})
    it 'should contain key "user_llll"' do
      expect(access).to have_key('user_llll')
    end

    it 'should contain key "user_mmmm"' do
      expect(access).to have_key('user_mmmm')
    end

    it 'should have a hash count equal to 2' do
      expect(access.length).to eq(2)
    end

    it 'should contain 21 descriptions of access' do
      expect(access['user_llll'].count + access['user_mmmm'].count).to eq(21)
    end
  end

  describe 'query single host "host_00008"' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:hosts => 'host_00008'})

    combined_access = []
    access.each do |k,v|
      v.each do |chunk|
        combined_access << chunk
      end
    end

    it 'should contain array(s) with only a single host in position [0]' do
      expect(combined_access.map {|chunk| chunk[0]}.uniq.length).to eq(1)
    end

    it 'should have that single host be "host_00008"' do
      expect(combined_access.map {|chunk| chunk[0]}.uniq[0]).to eq(parser.get_lookup_key('host_00008'))
    end

    it 'should contain 6 descriptions of access' do
      expect(combined_access.count).to eq(6)
    end
  end

  describe 'query multiple hosts "host_00008" and "host_00010"' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:hosts => 'host_00008,host_00010'})

    combined_access = []
    access.each do |k,v|
      v.each do |chunk|
        combined_access << chunk
      end
    end

    it 'should contain array(s) with only two hosts in position [0]' do
      expect(combined_access.map {|chunk| chunk[0]}.uniq.length).to eq(2)
    end

    it 'should contain a host "host_00008"' do
      expect(combined_access.map {|chunk| chunk[0]}.uniq).to include(parser.get_lookup_key('host_00008'))
    end

    it 'should contain a host "host_00010"' do
      expect(combined_access.map {|chunk| chunk[0]}.uniq).to include(parser.get_lookup_key('host_00010'))
    end

    it 'should contain 8 descriptions of access' do
      expect(combined_access.count).to eq(8)
    end
  end

  describe 'query single runas "acct_eeee' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:runas => 'acct_eeee'})

    combined_access = []
    access.each do |k,v|
      v.each do |chunk|
        combined_access << chunk
      end
    end

    it 'should contain array(s) with only a single runas in position [1]' do
      expect(combined_access.map {|chunk| chunk[1]}.uniq.length).to eq(1)
    end

    it 'should have that single runas be "acct_eeee"' do
      expect(combined_access.map {|chunk| chunk[1]}.uniq[0]).to eq(parser.get_lookup_key('acct_eeee'))
    end

    it 'should contain 6 descriptions of access' do
      expect(combined_access.count).to eq(6)
    end
  end

  describe 'query multiple runas "acct_eeee" and "acct_iiii"' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:runas => 'acct_eeee,acct_iiii'})

    combined_access = []
    access.each do |k,v|
      v.each do |chunk|
        combined_access << chunk
      end
    end

    it 'should contain array(s) with only two runas in position [1]' do
      expect(combined_access.map {|chunk| chunk[1]}.uniq.length).to eq(2)
    end

    it 'should contain a runas "acct_eeee"' do
      expect(combined_access.map {|chunk| chunk[1]}.uniq).to include(parser.get_lookup_key('acct_eeee'))
    end

    it 'should contain a runas "acct_iiii"' do
      expect(combined_access.map {|chunk| chunk[1]}.uniq).to include(parser.get_lookup_key('acct_iiii'))
    end

    it 'should contain 8 descriptions of access' do
      expect(combined_access.count).to eq(8)
    end
  end

  describe 'query single flag "NOPASSWD:"' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:flags => 'NOPASSWD:'})

    combined_access = []
    access.each do |k,v|
      v.each do |chunk|
        combined_access << chunk
      end
    end

    it 'should contain array(s) with only a single flag in position [2]' do
      expect(combined_access.map {|chunk| chunk[2]}.uniq.length).to eq(1)
    end

    it 'should have that single flag be "NOPASSWD:"' do
      expect(combined_access.map {|chunk| chunk[2]}.uniq[0]).to eq(parser.get_flag_number('NOPASSWD:'))
    end

    it 'should contain 12 descriptions of access' do
      expect(combined_access.count).to eq(12)
    end
  end

  describe 'query single command "/usr/bin/commmand12"' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:commands => '/usr/bin/command12'})

    combined_access = []
    access.each do |k,v|
      v.each do |chunk|
        combined_access << chunk
      end
    end

    it 'should contain array(s) with only a single command in position [3]' do
      expect(combined_access.map {|chunk| chunk[3]}.uniq.length).to eq(1)
    end

    it 'should have that single command be "/usr/bin/commmand12"' do
      expect(combined_access.map {|chunk| chunk[3]}.uniq[0]).to eq(parser.get_lookup_key('/usr/bin/command12'))
    end

    it 'should contain 6 descriptions of access' do
      expect(combined_access.count).to eq(6)
    end
  end

  describe 'query multiple commands "/usr/bin/command12" and "/usr/bin/command15"' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:commands => '/usr/bin/command12,/usr/bin/command15'})

    combined_access = []
    access.each do |k,v|
      v.each do |chunk|
        combined_access << chunk
      end
    end

    it 'should contain array(s) with only two commands in position [3]' do
      expect(combined_access.map {|chunk| chunk[3]}.uniq.length).to eq(2)
    end

    it 'should contain a command "/usr/bin/command12"' do
      expect(combined_access.map {|chunk| chunk[3]}.uniq).to include(parser.get_lookup_key('/usr/bin/command12'))
    end

    it 'should contain a command "/usr/bin/command15"' do
      expect(combined_access.map {|chunk| chunk[3]}.uniq).to include(parser.get_lookup_key('/usr/bin/command15'))
    end

    it 'should contain 12 descriptions of access' do
      expect(combined_access.count).to eq(12)
    end
  end
end

describe 'parser behavior' do
  describe 'query for command with escaped comma' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:users => 'user_aaaa', :hosts => 'host_00007', :commands => '/usr/bin/command13 \, "comma escape test"'})

    it 'should contain a command escaping a comma' do
      expect(access['user_aaaa'][0][3]).to include(parser.get_lookup_key('/usr/bin/command13 \, "comma escape test"'))
    end
  end

  describe 'should be able to handle escaped backslashes' do
    parser = DetangleSu::Parser.new(:filepath => './test/', :filename => 'sudoers')
    access = query_by_options(parser, options={:users => 'user_jjjj', :hosts => 'host_00006', :commands => '/usr/bin/command11 \\\\ "backslash escape test"'})

    it 'should contain a command escaping a backslash' do
      expect(access['user_jjjj'][0][3]).to include(parser.get_lookup_key('/usr/bin/command11 \\\\ "backslash escape test"'))
    end
  end
end

