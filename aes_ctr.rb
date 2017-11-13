require 'openssl'

require_relative 'xor'

def ctr(bytes, key:, nonce:)
  pad = ->(n) {
    p = n.digits(256)
    raise "Too big: #{p}" if p.size > 8
    p.concat([0] * (8 - p.size))
  }

  padded_nonce = pad[nonce]
  to_encrypt = (0...(bytes.size / 16.0).ceil).flat_map { |n| padded_nonce + pad[n] }.pack('c*')

  cipher = OpenSSL::Cipher::AES.new(128, :ECB).encrypt
  cipher.key = key

  xor(bytes, (cipher.update(to_encrypt) + cipher.final).bytes)
end
