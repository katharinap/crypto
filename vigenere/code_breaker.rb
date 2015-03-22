module Vigenere
  module CodeBreaker
    # determines the most likely key length used for the given
    # encrypted message by comparing the index of coincidence
    class KeyLength
      class << self
        def find(upper_limit, encrypted_message)
          best_match = (1..upper_limit).map do |key_length|
            new(key_length, encrypted_message)
          end.sort_by(&:index_of_coincidence).last

          best_match.key_length
        end
      end

      attr_reader :key_length, :encrypted_message

      def initialize(key_length, encrypted_message)
        @key_length = key_length
        @encrypted_message = encrypted_message
      end

      def index_of_coincidence
        (0..key_length - 1).inject do |sum, key_position|
          res = index_of_coincidence_for_position(key_position) / key_length
          sum + res
        end
      end

      private

      def message
        @message ||= encrypted_message.gsub(/(..)/, '\1 ').rstrip.split
      end

      def index_of_coincidence_for_position(key_position)
        chars = chars_for_position(key_position)

        (0..255).inject do |sum, n|
          hex_val = n.to_s(16).upcase
          ct = chars.count(hex_val)
          sum + ct * (ct - 1)
        end / (chars.size * (chars.size - 1)).to_f
      end

      def chars_for_position(key_position)
        chars = []
        idx = key_position
        while idx < message.size
          chars << message[idx]
          idx += key_length
        end
        chars
      end
    end

    # determines the most likely encryption key of the given length
    # evaluating the frequency of lower case letters
    class Decoder
      attr_reader :encrypted_chars, :key_length

      def initialize(encrypted_message)
        @key_length = KeyLength.find(13, encrypted_message)
        fail 'Failed to determine key length' if key_length.nil?
        puts "Found most likely key length #{key_length}"
        @encrypted_chars = encrypted_message.gsub(/(..)/, '\1 ').rstrip.split
      end

      def original_message
        key_elements = key_ascii_idx.cycle
        encrypted_chars.map do |hex_char|
          hex_char.to_i(16) ^ key_elements.next
        end.map(&:chr).join
      end

      def key
        key_ascii_idx.map { |i| i.to_s(16).upcase }
      end

      private

      # ascii representation of the most likely key (array of integers)
      def key_ascii_idx
        @key_ascii_idx ||= (0..key_length - 1).map do |key_position|
          key_element(key_position)
        end
      end

      # returns the ascii idx for that key that gives the most likely
      # result for a simply cypher shift for the given key_position
      def key_element(key_position)
        (0..255).map do |ascii_idx|
          FrequencyAnalysis.new(chars_for_position(key_position), ascii_idx)
        end.sort_by(&:result).last.ascii_idx
      end

      def chars_for_position(key_position)
        chars = []
        idx = key_position
        while idx < encrypted_chars.size
          chars << encrypted_chars[idx]
          idx += key_length
        end
        chars
      end
    end

    # determines the frequency of lower case letters resulting from a
    # shift cypher of the given ascii key (integer value) and an array
    # of encrypted hex characters
    class FrequencyAnalysis
      LETTER_FREQUENCY = {
        'a' => 8.167,
        'b' => 1.492,
        'c' => 2.782,
        'd' => 4.253,
        'e' => 12.702,
        'f' => 2.228,
        'g' => 2.015,
        'h' => 6.094,
        'i' => 6.966,
        'j' => 0.153,
        'k' => 0.772,
        'l' => 4.025,
        'm' => 2.406,
        'n' => 6.749,
        'o' => 7.507,
        'p' => 1.929,
        'q' => 0.095,
        'r' => 5.987,
        's' => 6.327,
        't' => 9.056,
        'u' => 2.758,
        'v' => 0.978,
        'w' => 2.360,
        'x' => 0.150,
        'y' => 1.974,
        'z' => 0.074
      }

      attr_reader :chars, :ascii_idx
      def initialize(chars, ascii_idx)
        @chars = chars
        @ascii_idx = ascii_idx
      end

      def result
        return 0 if decyphered_ascii_idx.any? { |n| invalid_ascii_idx?(n) }
        decyphered_ascii_idx.inject(0) do |sum, n|
          # we only count lower case letters and ignore upper case
          # letters or punctuation
          sum += LETTER_FREQUENCY.fetch(n.chr) { 0 }
        end / chars.size
      end

      private

      def invalid_ascii_idx?(idx)
        idx < 32 || idx > 127
      end

      def decyphered_ascii_idx
        @decyphered_ascii_idx ||= chars.map { |c| c.to_i(16) ^ ascii_idx }
      end
    end
  end
end
