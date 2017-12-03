require_relative 'assert'
require_relative 'mdpad'

def md4(message, hash_words = nil, add_to_length = 0)
  mask = (1 << 32) - 1
  f = ->(x, y, z) { x & y | x.^(mask) & z }
  g = ->(x, y, z) { x & y | x & z | y & z }
  h = ->(x, y, z) { x ^ y ^ z }
  r = ->(v, s) { (v << s).&(mask) | (v.&(mask) >> (32 - s)) }

  # initial hash
  a, b, c, d = hash_words || [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

  words = mdpad(message, :little, add_to_length).unpack('V*')

  words.each_slice(16) { |x|
    # Process this block.
    aa, bb, cc, dd = a, b, c, d
    [0, 4, 8, 12].each { |i|
      a = r[a + f[b, c, d] + x[i],  3]; i += 1
      d = r[d + f[a, b, c] + x[i],  7]; i += 1
      c = r[c + f[d, a, b] + x[i], 11]; i += 1
      b = r[b + f[c, d, a] + x[i], 19]
    }
    [0, 1, 2, 3].each { |i|
      a = r[a + g[b, c, d] + x[i] + 0x5a827999,  3]; i += 4
      d = r[d + g[a, b, c] + x[i] + 0x5a827999,  5]; i += 4
      c = r[c + g[d, a, b] + x[i] + 0x5a827999,  9]; i += 4
      b = r[b + g[c, d, a] + x[i] + 0x5a827999, 13]
    }
    [0, 2, 1, 3].each { |i|
      a = r[a + h[b, c, d] + x[i] + 0x6ed9eba1,  3]; i += 8
      d = r[d + h[a, b, c] + x[i] + 0x6ed9eba1,  9]; i -= 4
      c = r[c + h[d, a, b] + x[i] + 0x6ed9eba1, 11]; i += 8
      b = r[b + h[c, d, a] + x[i] + 0x6ed9eba1, 15]
    }
    a = (a + aa) & mask
    b = (b + bb) & mask
    c = (c + cc) & mask
    d = (d + dd) & mask
  }

  [a, b, c, d].pack('V4').unpack('H*')[0]
end

[
  ['', '31d6cfe0d16ae931b73c59d7e0c089c0'],
  ['a', 'bde52cb31de33e46245e05fbdbd6fb24'],
  ['abc', 'a448017aaf21d8525fc10ae87aa6729d'],
  ['message digest', 'd9130a8164549fe818874806e1c7014b'],
  ['abcdefghijklmnopqrstuvwxyz', 'd79e1c308aa5bbcdeea8ed63df412da9'],
  ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', '043f8582f241db351ce627e153e7f0e4'],
  ['12345678901234567890123456789012345678901234567890123456789012345678901234567890', 'e33b4ddc9c38f2199c3e7b164fcc0536'],
].each { |i, h|
  assert_eq(h, md4(i), i)
}

KEY = Array.new(rand(10) + 20) { rand(256) }.pack('c*').freeze

def good?(msg, mac)
  md4(KEY + msg) == mac
end

original_message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'.freeze

original_hash = md4(KEY + original_message)
# This should be obvious, but we'll do it anyway.
assert_eq(true, good?(original_message, original_hash))

string_to_add = ';admin=true'.freeze

new_hash = md4(string_to_add, [original_hash].pack('H*').unpack('V4'), 1024)

right_message = (0..128).map { |n|
  mdpad(?x * n + original_message, :little)[n..-1] + string_to_add
}.find { |s| good?(s, new_hash) }

assert_eq(false, right_message.nil?)
# We already ensure this through the `find` above, but whatever.
assert_eq(true, good?(right_message, new_hash))
