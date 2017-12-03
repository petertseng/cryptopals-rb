require_relative 'mdpad'

def leftrotate(value, shift)
  ((value << shift) | (value >> (32 - shift))) & 0xffffffff
end

# https://gist.github.com/tstevens/925415/6dd06487a8fcd5c4c3c9c18ee32eb60e2917b815
# FIPS 180-2 -- relevant section #'s below
def sha1(message, hash_words = nil, add_to_length = 0)
  hash_words ||= [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0] # 5.3.1

  # 5.1.1
  # Big-endian u_int32 chunks
  pad_string = mdpad(message, :big, add_to_length).unpack('N*')

  # 6.1.2
  pad_string.each_slice(16).each do |chunk| # Split pad_string into 512b chunks (16 * 32b) -- 6.1.2 - 1. Prepare the message schedule
    #Expand from sixteen to eighty -- 6.1.2 - 1. Prepare the message schedule
    (16..79).each { |i| chunk << leftrotate(chunk[i-3] ^ chunk[i-8] ^ chunk[i-14] ^ chunk[i-16], 1) }
    working_vars = hash_words.dup # Copy current hash_words for next round. -- 6.1.2 - 2. Initialize the five working variables.

    # 6.1.2 - 3. & 4.1.1 - SHA-1 Functions
    (0..79).each { |i|
      if 0 <= i && i <= 19
        f = (working_vars[1] & working_vars[2]) | (~working_vars[1] & working_vars[3])
        k = 0x5A827999
      elsif 20 <= i && i <= 39
        f = working_vars[1] ^ working_vars[2] ^ working_vars[3]
        k = 0x6ED9EBA1
      elsif 40 <= i && i <= 59
        f = (working_vars[1] & working_vars[2]) | (working_vars[1] & working_vars[3]) | (working_vars[2] & working_vars[3])
        k = 0x8F1BBCDC
      elsif 60 <= i && i <= 79
        f = working_vars[1] ^ working_vars[2] ^ working_vars[3]
        k = 0xCA62C1D6
      end
      # Complete round & Create array of working variables for next round.
      temp = (leftrotate(working_vars[0], 5) + f + working_vars[4] + k + chunk[i]) & 0xffffffff
      working_vars = [temp, working_vars[0], leftrotate(working_vars[1], 30), working_vars[2], working_vars[3]]
    }

    # 6.1.2 - 4. Compute the ith intermediate hash value
    hash_words = working_vars.zip(hash_words).map { |wv, hw| (hw + wv) & 0xffffffff }
  end

  # Block: Append string with hex formatted partial result, padding 0's due to ruby truncating leading 0's from hex output
  hash_words.map { |partial| partial.to_s(16).rjust(8, ?0) }.join
end
