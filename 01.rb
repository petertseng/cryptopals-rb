require 'base64'
require 'openssl'

def hex_to_bytes(s)
  s.chars.each_slice(2).map { |a| Integer(a.join, 16) }
end

def bytes_to_hex(l)
  l.map { |b| '%02x' % b }.join
end

def assert_eq(want, got, msg)
  raise "No on #{msg}, got #{got}, want #{want}" if got != want
end

# Set 1 Challenge 1: hex_to_base64
def hex_to_base64(s)
  Base64.strict_encode64(hex_to_bytes(s).pack('c*'))
end

assert_eq(
  'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t',
  hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'),
  'Set 1 Challenge 1',
)

def xor(a, b)
  a.zip(b).map { |x, y| x ^ y }
end

assert_eq(
  '746865206b696420646f6e277420706c6179',
  bytes_to_hex(xor(hex_to_bytes('1c0111001f010100061a024b53535009181c'), hex_to_bytes('686974207468652062756c6c277320657965'))),
  'Set 1 Challenge 2',
)

def xor_repeating(a, b)
  xor(a, b * (1 + a.size / b.size))
end

def xor_single(a, b)
  xor(a, [b] * a.size)
end

ENGLISH_FREQ = [
  0.08167,
  0.01492,
  0.02782,
  0.04253,
  0.12702,
  0.02228,
  0.02015,
  0.06094,
  0.06966,
  0.00153,
  0.00772,
  0.04025,
  0.02406,
  0.06749,
  0.07507,
  0.01929,
  0.00095,
  0.05987,
  0.06327,
  0.09056,
  0.02758,
  0.00978,
  0.02361,
  0.00150,
  0.01974,
  0.00074,
].freeze

def crack_single(bytes, must_be_printable: true)
  scores = (0...256).map { |i|
    candidate = xor_single(bytes, i)
    next [i, 1.0 / 0.0] if must_be_printable && !candidate.all? { |c|
      # Allow newlines
      c == 10 || (32..127).cover?(c)
    }
    str = candidate.pack('c*')
    lower_english_only = str.downcase.each_char.select { |c| (?a..?z).cover?(c) }
    freqs = lower_english_only.group_by(&:itself).transform_values(&:size)
    [
      i,
      ENGLISH_FREQ.zip(?a..?z).map { |expect_freq, letter|
        got_freq = (freqs[letter]&.to_f &./ lower_english_only.size) || 0
        (expect_freq - got_freq).abs
      }.sum
    ]
  }

  best_byte, best_score = scores.min_by(&:last)

  best_score.finite? ? [best_byte, xor_single(bytes, best_byte), best_score] : nil
end

assert_eq(
  'Cooking MC\'s like a pound of bacon',
  crack_single(
    hex_to_bytes('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'),
    must_be_printable: true,
  )[1].pack('c*'),
  'Set 1 Challenge 3',
)

candidates = File.read('0104.txt').lines

def detect(candidates)
  best = candidates.map { |c|
    crack_single(hex_to_bytes(c.strip), must_be_printable: true)
  }.compact.min_by(&:last)
  best[1].pack('c*')
end

assert_eq(
  "Now that the party is jumping\n",
  detect(candidates),
  'Set 1 Challenge 4',
)

assert_eq(
  '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f',
  bytes_to_hex(xor_repeating(
    "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".bytes,
    'ICE'.bytes
  )),
  'Set 1 Challenge 5',
)

BITS = (0...256).map { |x| x.to_s(2).count(?1) }.freeze

def hamming_distance(a, b)
  a.zip(b).map { |x, y| BITS[x ^ y] }.sum
end

assert_eq(
  37,
  hamming_distance('this is a test'.bytes, 'wokka wokka!!!'.bytes),
  'Set 1 Challenge 6 (auxiliary)',
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

bytes = Base64.decode64(File.read('0106.txt')).bytes
key = crack_viginere(bytes)

assert_eq(
  [84, 101, 114, 109, 105, 110, 97, 116, 111, 114, 32, 88, 58, 32, 66, 114, 105, 110, 103, 32, 116, 104, 101, 32, 110, 111, 105, 115, 101],
  key,
  'Set 1 Challenge 6',
)

#puts xor_repeating(bytes, key).pack('c*')

bytes = Base64.decode64(File.read('0107.txt'))
cipher = OpenSSL::Cipher::AES.new(128, :ECB).decrypt
cipher.key = 'YELLOW SUBMARINE'
#puts cipher.update(bytes)
