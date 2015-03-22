require_relative '../one_time_pad'

module OTP
  describe EncryptedMessage do
    let(:m0) { EncryptedMessage.new '66', id: 'm0' }
    let(:m1) { EncryptedMessage.new '32', id: 'm1' }
    let(:m2) { EncryptedMessage.new '23', id: 'm2' }

    describe 'analyze_messages' do
      it 'compares the known message objects and determines their plain text' do
        MessageAnalyzer.new(m1, m0, m2).call
        expect(m0.plain_text).to eq(' ')
        expect(m1.plain_text).to eq('t')
        expect(m2.plain_text).to eq('e')
      end
    end

    describe '.binary' do
      it 'returns an array of binary strings' do
        expect(m0.send :binary_array).to eq(%w(01100110))
        expect(m1.send :binary_array).to eq(%w(00110010))
        expect(m2.send :binary_array).to eq(%w(00100011))
      end
    end
  end
end
