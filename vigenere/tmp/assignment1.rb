#! /usr/bin/env ruby

encrypted_message = File.read('cyphertext.txt').strip

class KeyLengthAnalyzer
  class << self
    def max(upper_limit, encrypted_message)
      vals = Hash[
        (1..upper_limit).map do |key_length|
          k = new(key_length, encrypted_message)
          [key_length, k.occurence_val]
        end
      ]
      vals.each { |k, v| puts "key length #{k} => #{v*100}" }
      max_val = vals.values.max
      key_length = vals.key(max_val)
      puts "key length: #{key_length}"
      key_length
    end
  end
  
  attr_reader :key_length, :message

  def initialize(key_length, message)
    @key_length = key_length
    @message = message.gsub(/(..)/,'\1 ').rstrip.split
  end

  def occurence_val
    result = []
    (0..key_length-1).each do |key_position|
      # puts "key_position #{key_position}"
      result << index_of_coincidence(chars_for_position(key_position))
    end
    result.reduce(:+) / key_length
  end

  private

  def index_of_coincidence(chars)
    (0..255).inject(0) do |sum, n|
      hex_val = n.to_s(16).upcase
      pn = (chars.count(hex_val).to_f - 1) / chars.size
      pn * pn
      # char = n.chr
      # frequency = LETTER_FREQUENCY.fetch(char)
      # chars.count(char) * frequency
    end
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

# KEY_LENGTH = KeyLengthAnalyzer.max(13, encrypted_message)
KEY_LENGTH = 7

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

class KeyAnalyzer
  attr_reader :key_length, :message

  def initialize(key_length, encrypted_message)
    @key_length = key_length
    @message = encrypted_message.gsub(/(..)/,'\1 ').rstrip.split
  end

  def call
    key = []
    (0..@key_length-1).each do |key_position|
      key << key_element(key_position)
    end

    result = []
    message.each_with_index do |hex_char, idx|
      key_idx = key[idx.divmod(@key_length).last]
      result << decypher(hex_char, key_idx)
    end
    puts result.join
  end

  def decypher(hex_char, ascii_idx)
    hex_to_str(str_to_hex(hex_char) ^ ascii_idx)
  end

  private

  def key_element(key_position)
    chars = chars_for_position(key_position) # array of hex strings
    props = []
    puts "key_position #{key_position}"
    key_elem = nil
    max_weight = 0
    (0..255).each do |ascii_idx|
      decyphered_chars = chars.map { |c| decypher(c, ascii_idx) }
      next if decyphered_chars.include?(nil)
      weight = lower_char_prop(decyphered_chars)
      if weight > max_weight
        max_weight = weight
        key_elem = ascii_idx
      end
      puts "idx #{ascii_idx} -> #{weight} #{decyphered_chars}"

      # puts "idx #{ascii_idx} -> #{decyphered_chars.inspect}"
    end
    key_elem
  end

  def decypher(hex_char, ascii_idx)
    hex_to_str(str_to_hex(hex_char) ^ ascii_idx)
  end

  def lower_char_prop(chars)
    sum = 0
    LETTER_FREQUENCY.each do |char, freq|
      char_count = chars.count(char)
      sum += char_count * freq / char.size
    end
    sum
  end
  
  def hex_to_str(num)
    if (32..127).to_a.include?(num)
      num.chr
    else
      nil
    end
    # num.to_s(16).rjust(2, '0')
  end

  def str_to_hex(str)
    str.to_i(16)
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


# KeyAnalyzer.new(2, 'E94ACD43CE0E').call
KeyAnalyzer.new(7, encrypted_message).call
