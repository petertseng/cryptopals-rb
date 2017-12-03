require_relative 'aes_ctr'
require_relative 'assert'

KEY = Array.new(16) { rand(256) }.pack('c*').freeze

PREFIX = 'comment1=cooking%20MCs;userdata='.bytes.freeze
SUFFIX = ';comment2=%20like%20a%20pound%20of%20bacon'.bytes.freeze

def encrypt(data)
  to_encrypt = PREFIX + data.tr(';=', '').bytes + SUFFIX
  nonce = rand(2 ** 64 - 1)
  [ctr(to_encrypt, key: KEY, nonce: nonce), nonce]
end

def is_admin(encrypted, nonce)
  ctr(encrypted, key: KEY, nonce: nonce).pack('c*').include?(';admin=true;')
end

not_semicolon = (?;.ord ^ 1).chr
not_equals = (?=.ord ^ 1).chr
attack_string = "#{not_semicolon}admin#{not_equals}true"

bytes, nonce = encrypt(attack_string)

attack_string.each_char.with_index { |c, i|
  next unless c == not_semicolon || c == not_equals
  # Flip the bit we want to flip, right?
  target_byte = i + PREFIX.size
  bytes[target_byte] ^= 1
}

assert_eq(true, is_admin(bytes, nonce))
