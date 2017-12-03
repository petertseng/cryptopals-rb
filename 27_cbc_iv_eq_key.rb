require_relative 'aes_cbc'
require_relative 'assert'
require_relative 'xor'

KEY = Array.new(16) { rand(256) }.freeze

def encrypt(bytes)
  aes_cbc_encrypt(bytes, key: KEY.pack('c*'), iv: KEY)
end

def check(bytes)
  decrypted = aes_cbc_decrypt(bytes, key: KEY.pack('c*'), iv: KEY)
  [decrypted, decrypted.all? { |a| a <= 127 }]
end

alphabet = (?a..?z).to_a

plaintext = Array.new(48) { alphabet.sample }.join.freeze
ciphertext = encrypt(plaintext.bytes).freeze

first_block = ciphertext[0, 16]
decrypted, _ = check(first_block + ([0] * 16) + first_block)

key = xor(decrypted[0, 16], decrypted[32, 16])
assert_eq(KEY, key)
