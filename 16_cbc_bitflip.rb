require_relative 'aes_cbc'
require_relative 'assert'

KEY = Array.new(16) { rand(256) }.pack('c*').freeze

PREFIX = 'comment1=cooking%20MCs;userdata='.bytes.freeze
SUFFIX = ';comment2=%20like%20a%20pound%20of%20bacon'.bytes.freeze

def encrypt(data)
  to_encrypt = PREFIX + data.tr(';=', '').bytes + SUFFIX
  pad_len = 16 - to_encrypt.size % 16
  to_encrypt.concat([pad_len] * pad_len)
  iv = Array.new(16) { rand(256) }.freeze
  [aes_cbc_encrypt(to_encrypt, key: KEY, iv: iv).freeze, iv]
end

def is_admin(encrypted, iv)
  aes_cbc_decrypt(encrypted, key: KEY, iv: iv).pack('c*').include?(';admin=true;')
end

# To make certain that our desired string is in a single block, let's pad.
pad = [0] * (16 - PREFIX.size % 16)
# We specifically make a block whose bytes we flip, but we could just use the previous block.
zeroes = [0] * 16
not_semicolon = (?;.ord ^ 1).chr
not_equals = (?=.ord ^ 1).chr
attack_string = "#{not_semicolon}admin#{not_equals}true"

orig, iv = encrypt(pad.pack('c*') + zeroes.pack('c*') + attack_string)
bytes = orig.dup

attack_string.each_char.with_index { |c, i|
  next unless c == not_semicolon || c == not_equals
  # flipping the bit in the zeroes block at the place we want to flip.
  target_byte = i + PREFIX.size + pad.size
  bytes[target_byte] ^= 1
}

assert_eq(true, is_admin(bytes, iv))
