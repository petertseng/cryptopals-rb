require_relative 'assert'
require_relative 'mt19937'
require_relative 'xor'

def encrypt(bytes, key:)
  r = MT19937.new(key)
  xor(bytes, bytes.map { r.rand })
end

assert_eq(text = 'asdfasdf'.bytes, encrypt(encrypt(text, key: (k = 19)), key: k))

key = rand(2**16)

known_plain = 'aaaa'.bytes.freeze
prefix = Array.new(rand(10) + 20) { rand(256) }.freeze

ciphertext = encrypt(prefix + known_plain, key: key)

expected = xor(known_plain, ciphertext.last(known_plain.size))

possible_keys = (0..2**16).select { |candidate|
  r = MT19937.new(candidate)
  ciphertext.map { r.rand }.last(known_plain.size) == expected
}

assert_eq([key], possible_keys)
