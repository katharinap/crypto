#! /usr/bin/env ruby

require_relative 'one_time_pad'

m1 = OTP::EncryptedMessage.new('BB3A65F6F0034FA957F6A767699CE7FABA855AFB4F2B520AEAD612944A801E', id: 'm1')
m2 = OTP::EncryptedMessage.new('BA7F24F2A35357A05CB8A16762C5A6AAAC924AE6447F0608A3D11388569A1E', id: 'm2')
m3 = OTP::EncryptedMessage.new('A67261BBB30651BA5CF6BA297ED0E7B4E9894AA95E300247F0C0028F409A1E', id: 'm3')
m4 = OTP::EncryptedMessage.new('A57261F5F0004BA74CF4AA2979D9A6B7AC854DA95E305203EC8515954C9D0F', id: 'm4')
m5 = OTP::EncryptedMessage.new('BB3A70F3B91D48E84DF0AB702ECFEEB5BC8C5DA94C301E0BECD241954C831E', id: 'm5')
m6 = OTP::EncryptedMessage.new('A6726DE8F01A50E849EDBC6C7C9CF2B2A88E19FD423E0647ECCB04DD4C9D1E', id: 'm6')
m7 = OTP::EncryptedMessage.new('BC7570BBBF1D46E85AF9AA6C7A9CEFA9E9825CFD5E3A0047F7CD009305A71E', id: 'm7')

m1.set_plain_char(0, 'I')
m1.set_plain_char(6, 'l')
m1.set_plain_char(8, 'n')
m1.set_plain_char(10, 'i')
m1.set_plain_char(17, 'e')
m1.set_plain_char(20, 'e')
m1.set_plain_char(29, 'n')
m4.set_plain_char(30, '?')

messages = [m1, m2, m3, m4, m5, m6, m7]
OTP::MessageAnalyzer.new(*messages).call

messages.each do |message|
  puts "#{message.id} -> #{message.plain_text}"
end
