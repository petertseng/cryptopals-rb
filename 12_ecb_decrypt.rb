require 'base64'
require 'openssl'

require_relative 'assert'

TO_APPEND = Base64.decode64('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK').bytes.freeze

KEY = Array.new(16) { rand(256) }.pack('c*').freeze

def ecb(bytes)
  to_encrypt = bytes + TO_APPEND
  cipher = OpenSSL::Cipher::AES.new(128, :ECB).encrypt
  cipher.key = KEY
  (cipher.update(to_encrypt.pack('c*')) + cipher.final).bytes
end

def ecb_block_size
  # I kind of combine steps 1 and 2 here (show it's ECB, plus find the block length)
  # One could do it separately by adding bytes until the first block no longer changes.
  2.step.find { |n|
    (a = ecb([0] * (n * 3)))[n, n] == a[2 * n, n]
  }
end

block_size = ecb_block_size
assert_eq(16, block_size, 'block size')
# prefix: the prefix we need to add before every trial block,
# so that it matches the prefix we expect to appear in the block containing the target byte.
# Starts out being all zeroes since we are padding with zeroes,
# but ends up being the previous (block_size - 1) bytes of what we've decrypted.
prefix = [0] * (block_size - 1)

decoded = (0...TO_APPEND.size).map { |i|
  # First 256 blocks (indices 0..255) are the prefix plus that byte.
  # If we're decoding the ith byte, we need to add zeroes to place the ith byte in the last of a block.
  #
  # So the block size is 4, the message is ABCDE? and we're currently trying to decrypt the ?, then we send (roughly):
  # CDEA <- trial bytes 0..255
  # CDEB
  # ...
  # 00AB <- padding zeroes, then the unknown string
  # CDE?
  bytes = (0...256).flat_map { |b| prefix + [b] } + [0] * (block_size - 1 - (i % block_size))
  result = ecb(bytes)
  target_block = result[(256 + i / block_size) * block_size, block_size]
  (0...256).find { |n|
    target_block == result[n * block_size, block_size]
  }.tap { |byte|
    prefix.shift
    prefix << byte
  }
}

puts decoded.pack('c*') if ARGV.include?('-v')

assert_eq("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n".bytes, decoded)
