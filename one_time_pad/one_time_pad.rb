#! /usr/bin/env ruby

require 'pry-byebug'
require 'logger'

# deals with decryption of messages that were encrypted with the one
# time pad algorithm which used a common key for the encryption
module OTP
  def binary_xor(binary_val1, binary_val2)
    (binary_val1.to_i(2) ^ binary_val2.to_i(2)).to_s(2)
  end
  module_function :binary_xor

  def log
    if @log.nil?
      @log = Logger.new(STDOUT)
      @log.level = Logger::WARN
      # @log.level = Logger::INFO
    end
    @log
  end
  module_function :log

  # compares the given EncryptedMessage objects (that were generated
  # with the same key) and determines the plain messages by looking
  # for pre-set characters and spaces.  As soon as one is found, the
  # plain text characters at the same position of all other messages
  # are known as well.
  class MessageAnalyzer
    attr_reader :messages

    # EncryptedMessage objects with potentially pre-set entries
    def initialize(*messages)
      @messages = messages
    end

    def call
      (0..messages.first.length - 1).each do |pos|
        analyze_position(pos)
      end
    end

    private

    # if one character at this position can be determined, we can get
    # the other messages' characters via xor as well.
    # The method sets the plain characters for each method in this
    # case.
    def analyze_position(pos)
      # get one message for which we know the character at this
      # position already
      message = known_message(pos)
      return if message.nil?

      # binary string representation of the known character
      known_binary_val = binary_for_char(message.plain_text[pos])

      messages.each do |m1|
        next if m1 == message
        # binary xor of the encrypted char with the encrypted char of
        # the known message
        known_xor = m1.binary_xor_at(pos, message)

        # we get the plain character by xor-ing with the value of the
        # known plain text char
        bin_val = OTP.binary_xor(known_xor, known_binary_val)

        # update the message object
        m1.set_plain_char(pos, bin_val.to_i(2).chr)
      end
    end

    # returns the 8bit binary string for the given character
    def binary_for_char(char)
      char.unpack('H*').first.to_i(16).to_s(2).rjust(8, '0')
    end

    # if one of the messages has a pre-set plain text character at the
    # given position, this message is returned.  If not, we look for a
    # space character in one of the messages
    def known_message(pos)
      message = message_with_pre_set_char(pos) || message_with_space(pos)
      OTP.log.warn "Failed to determine any character for position #{pos}" if message.nil?
      message
    end

    def message_with_pre_set_char(pos)
      message = messages.find { |m| m.plain_character_known?(pos) }
      OTP.log.info "#{pos} - Found pre-set character #{message.plain_text[pos]} in #{message.id}" if message
      message
    end

    # two letters xor      -> ^00
    # space and letter xor -> ^01
    def message_with_space(pos)
      message = messages.find do |m1|
        messages.none? { |m2| m1.binary_xor_at(pos, m2) =~ /^00.*1/ }
      end
      return nil if message.nil?

      OTP.log.info "#{pos} - Found space entry in #{message.id}"
      message.set_plain_char(pos, ' ')

      message
    end
  end

  # container class for encrypted and plain text
  class EncryptedMessage
    attr_reader :id
    def initialize(str, id: '')
      @message = hex_array(str)
      @plain_message = Array.new(@message.size, nil)
      @id = id
    end

    # at positions for which the plain text character is unknown, an
    # underscore is used as placeholder
    def plain_text
      @plain_message.map { |c| c.nil? ? '_' : c }.join
    end

    def set_plain_char(pos, char)
      @plain_message[pos] = char
    end

    def plain_character_known?(pos)
      !@plain_message[pos].nil?
    end

    def binary_xor_at(pos, other)
      OTP.binary_xor(binary_at(pos), other.binary_at(pos)).rjust(8, '0')
    end

    def length
      @message.length
    end

    protected

    # returns 8bit binary string of the encrypted text for given
    # position
    def binary_at(pos)
      @message[pos].to_i(16).to_s(2).rjust(8, '0')
    end

    def binary_array
      (0..length - 1).map { |pos| binary_at(pos) }
    end

    # splits the given string into elements of 2
    def hex_array(str)
      str.gsub(/(..)/, '\1 ').rstrip.split
    end
  end
end
