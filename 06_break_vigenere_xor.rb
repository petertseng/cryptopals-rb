require 'base64'

require_relative 'assert'
require_relative 'xor'

assert_eq(
  37,
  hamming_distance('this is a test'.bytes, 'wokka wokka!!!'.bytes),
  'auxiliary',
)

def crack_viginere(bytes)
  (2..40).map { |keysize|
    [
      keysize,
      (0..4).each_cons(2).map { |a, b|
        hamming_distance(bytes[a * keysize, keysize], bytes[b * keysize, keysize])
      }.sum.to_f / keysize,
    ]
  }.sort_by(&:last).each { |keysize, _|
    num_slices = (bytes.size.to_f / keysize).ceil
    # I'd use transpose, but that requires rectangle.
    transposed = (0...keysize).map { |n| (0...num_slices).map { |s| bytes[s * keysize + n] }.compact }
    key = transposed.map { |chunk|
      break unless (byte, _, _ = crack_single(chunk, must_be_printable: true))
      byte
    }
    return key if key
  }
end

bytes = Base64.decode64(File.read('data/06.txt')).bytes
key = crack_viginere(bytes)

assert_eq(
  [84, 101, 114, 109, 105, 110, 97, 116, 111, 114, 32, 88, 58, 32, 66, 114, 105, 110, 103, 32, 116, 104, 101, 32, 110, 111, 105, 115, 101],
  key,
)

puts xor_repeating(bytes, key).pack('c*') if ARGV.include?('-v')
