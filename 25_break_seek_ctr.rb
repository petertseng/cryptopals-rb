require 'base64'
require 'openssl'

require_relative 'aes_ctr'
require_relative 'assert'
require_relative 'xor'

module Secret
  ecb_ciphered = Base64.decode64(File.read('data/25.txt'))
  cipher = OpenSSL::Cipher::AES.new(128, :ECB).decrypt
  cipher.key = 'YELLOW SUBMARINE'

  # Note that plain, key, nonce, keystream are never to be exposed outside.
  plain = (cipher.update(ecb_ciphered) + cipher.final).bytes.freeze
  key = Array.new(16) { rand(256).chr }.join.freeze
  nonce = rand(2 ** 64 - 1)
  # To save time, I'm going to acquire the keystream by encrypting all zeroes.
  keystream = ctr([0] * plain.size, key: key, nonce: nonce).freeze

  CIPHERTEXT = xor(plain, keystream).freeze
  EDIT = ->(ct, n, pt) { ct[n, pt.size] = xor(keystream[n, pt.size], pt) }
  CHECK = ->(x) { assert_eq(plain, x) }

  def self.check(*args) CHECK[*args] end
  def self.edit(*args) EDIT[*args] end
end

# This would have been used to brute-force, but brute force is not necessary?!?!
#priority_chars = [' '.ord] + (?a..?z).map(&:ord) + (?A..?Z).map(&:ord) + ["\n".ord]
#other_printables = (32..127).to_a - priority_chars
#chars = priority_chars + other_printables + ((0..255).to_a - (priority_chars | other_printables))

# So I'm pretty sure I can recover the keystream by asking to write all zeroes.
keystream = Array.new(Secret::CIPHERTEXT.size)
Secret.edit(keystream, 0, keystream.map { 0 })
recovered_plaintext = xor(keystream, Secret::CIPHERTEXT)
puts recovered_plaintext.pack('c*') if ARGV.include?('-v')
Secret.check(recovered_plaintext)
