require 'openssl'

require_relative 'xor'

def aes_cbc_encrypt(bytes, key:, iv:)
  cipher = OpenSSL::Cipher::AES.new(128, :ECB).encrypt
  cipher.key = key
  prev = iv.freeze
  bytes.each_slice(16).flat_map { |block|
    prev = cipher.update(xor(block, prev).pack('c*')).bytes.freeze
  }
end

def aes_cbc_decrypt(bytes, key:, iv:)
  cipher = OpenSSL::Cipher::AES.new(128, :ECB).decrypt
  cipher.key = key
  # If I don't do this, I get a "bad decrypt" when calling cipher.final.
  cipher.padding = 0
  decrypted = cipher.update(bytes.pack('c*')).bytes + cipher.final.bytes
  decrypted.each_slice(16).flat_map.with_index { |block, i|
    xor(block, i == 0 ? iv : bytes[(i - 1) * 16, 16])
  }
end
