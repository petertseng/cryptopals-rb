require 'base64'
require 'openssl'

require_relative 'assert'

# This is mostly the same as 12,
# so it could be instructive to look at the diff between 12 and 14.

TO_APPEND = Base64.decode64('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK').bytes.freeze

KEY = Array.new(16) { rand(256) }.pack('c*').freeze

def ecb(bytes)
  # Randomly prepend 5 to 100 bytes.
  to_encrypt = Array.new(rand(96) + 5) { rand(256) } + bytes + TO_APPEND
  cipher = OpenSSL::Cipher::AES.new(128, :ECB).encrypt
  cipher.key = KEY
  (cipher.update(to_encrypt.pack('c*')) + cipher.final).bytes
end

def ecb_block_size
  # I kind of combine steps 1 and 2 here (show it's ECB, plus find the block length)
  # One could do it separately by adding bytes until the first block no longer changes.
  2.step.find { |n|
    ecb([0] * (n * 3)).each_slice(n).each_cons(2).any? { |a, b| a == b }
  }
end

block_size = ecb_block_size
assert_eq(16, block_size, 'block size')
# prefix: the prefix we need to add before every trial block,
# so that it matches the prefix we expect to appear in the block containing the target byte.
# Starts out being all zeroes since we are padding with zeroes,
# but ends up being the previous (block_size - 1) bytes of what we've decrypted.
prefix = [0] * (block_size - 1)

# Assume that the random prefix and target string contain no repeating blocks.
# In that case, add three canary blocks that we should expect to be equal,
# then look for them to see how long the prefix is.
# Prepend a block of zeroes to prevent a false positive,
# which would otherwise occur if the last bytes in random prefix == last bytes in canary.
canary = ([0] * block_size + (1..block_size).to_a * 3).freeze

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
  result = loop {
    # We just keep trying until we see our canary blocks are equal,
    # then we know the random prefix was the right length.
    try = ecb(canary + bytes)
    prefix_blocks = (0..6).find { |n|
      (1..2).all? { |m| try[(n + 1) * block_size, block_size] == try[(n + 1 + m) * block_size, block_size] }
    }
    next unless prefix_blocks
    # Cut off the random prefix plus canary.
    try.shift(prefix_blocks * block_size + canary.size)
    break try
  }
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
