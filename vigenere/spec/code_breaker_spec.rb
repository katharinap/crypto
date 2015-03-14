require_relative '../code_breaker'

module Vigenere
  module CodeBreaker 
    ENCRYPTED_TEXT = File.read(File.expand_path('../../data/cyphertext.txt', __FILE__))

    describe KeyLength do
      describe 'find' do
        it 'returns the most likely key length for the given encrypted message' do
          expect(KeyLength.find(13, ENCRYPTED_TEXT)).to eq(7)
        end
      end
    end

    describe Decoder do
      describe 'new' do
        it 'determines the most likely key and the decrypted message for the given key length and encrypted message' do
          dec = Decoder.new(7, ENCRYPTED_TEXT)

          key =  %w(BA 1F 91 B2 53 CD 3E)
          decrypted_message = 'Cryptography is the practice and study of techniques for, among other things, secure communication in the presence of attackers. Cryptography has been used for hundreds, if not thousands, of years, but traditional cryptosystems were designed and evaluated in a fairly ad hoc manner. For example, the Vigenere encryption scheme was thought to be secure for decades after it was invented, but we now know, and this exercise demonstrates, that it can be broken very easily.'
          expect(dec.key).to eq(key)
          expect(dec.original_message).to eq(decrypted_message)
        end
      end
    end
  end
end
