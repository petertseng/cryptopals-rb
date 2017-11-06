require 'openssl'

require_relative 'aes_cbc'
require_relative 'assert'

def maybe_cbc(bytes)
  rand_bytes = -> { Array.new(rand(6) + 5) { rand(256) } }
  key = Array.new(16) { rand(256) }.pack('c*')

  type = %i(ecb cbc).sample

  to_encrypt = rand_bytes[] + bytes + rand_bytes[]

  [type, case type
  when :ecb
    cipher = OpenSSL::Cipher::AES.new(128, :ECB).encrypt
    cipher.key = key
    (cipher.update(to_encrypt.pack('c*')) + cipher.final).bytes
  when :cbc
    aes_cbc_encrypt(to_encrypt, key: key, iv: Array.new(16) { rand(256) })
  else raise "Bad type #{type}"
  end
  ]
end

def ecb?(bytes)
  freq = bytes.each_slice(16).group_by(&:itself).transform_values(&:size)
  freq.values.any? { |n| n > 1 }
end

100.times {
  type, bytes = maybe_cbc([0] * 64)
  assert_eq(type == :ecb, ecb?(bytes), "Type of #{bytes} (it's actually #{type})")
}
