require 'base64'

require_relative 'aes_cbc'
require_relative 'assert'

STRS = %w(
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
).map { |s| Base64.decode64(s).freeze }.freeze

KEY = Array.new(16) { rand(256) }.pack('c*').freeze

def encrypt(to_encrypt)
  pad_len = 16 - to_encrypt.size % 16
  to_encrypt.concat([pad_len] * pad_len)
  iv = Array.new(16) { rand(256) }.freeze
  [aes_cbc_encrypt(to_encrypt, key: KEY, iv: iv).freeze, iv]
end

def decrypt_padded?(encrypted, iv:)
  bytes = aes_cbc_decrypt(encrypted, key: KEY, iv: iv)
  pad = bytes.last(bytes.last)
  pad.all? { |x| x == pad[0] } && pad.size == pad[0]
end

def with_xor(a, idx, with)
  xor = ->() { with.each_with_index { |w, i| a[idx + i] ^= w } }
  xor[]
  yield.tap { xor[] }
end

STRS.each { |s|
  orig_bytes, orig_iv = encrypt(s.bytes)
  bytes = orig_bytes.dup
  iv = orig_iv.dup

  assert_eq(true, decrypt_padded?(orig_bytes, iv: iv), 'original message padded')
  assert_eq(0, orig_bytes.size % 16, 'original message length in block size')

  decrypted = bytes.map { nil }

  (0...(orig_bytes.size / 16)).each { |block|
    (1..16).each { |target_pad|
      # Position of this byte in full message, as a negative (from the end)
      i = -block * 16 - target_pad

      # Byte one block ahead of the byte we're decrypting (target byte):
      to_be_xored, idx = bytes.size == 16 ? [iv, -target_pad] : [bytes, -16 - target_pad]

      # Prepare the bytes coming after the target byte.
      # They should all contain the target_pad.
      possibilities = with_xor(to_be_xored, idx + 1, (0...(target_pad - 1)).map { |b| decrypted[i + 1 + b] ^ target_pad }) {
        orig = to_be_xored[idx]
        (0..255).select { |n|
          # XOR the target byte and see if it contains the target_pad
          # If so, n ^ target_pad is possible value for target byte.
          to_be_xored[idx] = orig ^ n
          decrypt_padded?(bytes, iv: iv)
        }.tap { to_be_xored[idx] = orig }
      }

      decrypted[i] = if possibilities == [0]
        target_pad
      elsif (nonzero_possibilities = possibilities - [0]).size == 1
        nonzero_possibilities[0] ^ target_pad
      else
        raise "#{i}: Ambiguous (#{possibilities.size}): #{possibilities}"
      end
    }
    bytes.pop(16)
  }

  # Remove padding
  decrypted.pop(decrypted.last)

  assert_eq(s, decrypted.pack('c*'))
}
