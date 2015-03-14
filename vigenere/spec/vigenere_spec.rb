require_relative '../vigenere'

module Vigenere
  describe CypherText do
    describe '.encrypt' do
      it 'returns the cyphertext resulting for the given key' do
        expect(CypherText.new('Hello!').encrypt(%w(A1 2F))).to eq('E94ACD43CE0E')
      end
    end

    describe '.decrypt' do
      it 'returns the plaintext resulting for the given key' do
        expect(CypherText.new('E94ACD43CE0E').decrypt(%w(A1 2F))).to eq('Hello!')
      end
    end
  end

  ENCRYPTED_TEXT = File.read(File.expand_path('../../data/cyphertext.txt', __FILE__))
  
  describe KeyLengthAnalyzer do
    describe '.find' do
      it 'returns the most likely key length for the given encrypted message' do
        expect(KeyLengthAnalyzer.find(13, ENCRYPTED_TEXT)).to eq(7)
      end
    end
  end
end

