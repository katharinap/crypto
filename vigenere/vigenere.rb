#! /usr/bin/env ruby

module Vigenere
  # encryption and decryption using the Vigenere algorithm (encrypted
  # text is represented in hex characters instead of ascii
  class CypherText
    attr_reader :message

    def initialize(message)
      @message = message
    end

    def encrypt(key)
      xor(convert_to_hex(message), key).join.upcase
    end

    def decrypt(key)
      convert_to_str xor(hex_array(message), key)
    end

    private

    # returns the result of xor-in the given hex characters with the
    # key (array of hex characters as well
    def xor(hex_chars, key)
      key_elements = key.cycle
      hex_chars.map do |hex_char|
        hex_to_str(str_to_hex(hex_char) ^ str_to_hex(key_elements.next))
      end
    end

    # returns the string representation of the given hex number
    #  9 => '09'
    # 10 => '0a'
    def hex_to_str(hex_num)
      hex_num.to_s(16).rjust(2, '0')
    end

    # returns the ascii char corresponding to the given hex num
    def hex_to_char(hex_num)
      hex_num.chr
    end

    # returns the hex num corresponding to the given string
    # representation
    def str_to_hex(str)
      str.to_i(16)
    end

    # converts the given plain text into an array of hex values
    # (strings)
    def convert_to_hex(text)
      hex_array(text.unpack('H*').first)
    end

    def convert_to_str(hex_ary)
      hex_ary.map { |v| v.to_i(16) }.pack('c*')
    end

    # splits the given string into elements of 2
    def hex_array(str)
      str.gsub(/(..)/, '\1 ').rstrip.split
    end
  end
end
