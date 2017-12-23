require_relative 'aes_cbc'
require_relative 'assert'

KEY = 'YELLOW SUBMARINE'.freeze
IV = ([0] * 16).freeze
TARGET_HASH = '296b8d7cb78a243dda4d0a61d33bbdd1'.each_char.each_slice(2).map { |x|
  x.join.to_i(16)
}.freeze

def cbc_mac_hash(p)
  pad_len = 16 - p.size % 16
  c = aes_cbc_encrypt(p + [pad_len] * pad_len, key: KEY, iv: IV)
  c[-16..-1]
end

assert_eq(
  TARGET_HASH,
  cbc_mac_hash("alert('MZA who was that?');\n".bytes),
  'Target hash is correct'
)

prefix = "alert('Ayo, the Wu is back!');//".bytes
mac = cbc_mac_hash(prefix)

# We have a mac for "alert(Wu)//padding".
# What do we need to add to get the target hash?
#
#     | X1 xor mac | padding xor X2
#     | encrypt    | encrypt
# mac | X2         | TARGET

# x2 is xor(padding, decrypt(TARGET))
# the xor is equivalent to using the padding as the IV.
x2 = aes_cbc_decrypt(TARGET_HASH, key: KEY, iv: [16] * 16)
# Same here; xor with MAC is same using the MAC as the IV.
x1 = aes_cbc_decrypt(x2, key: KEY, iv: mac)

pad_len = 16 - prefix.size % 16
attack = prefix + [pad_len] * pad_len + x1

assert_eq(
  TARGET_HASH,
  cbc_mac_hash(attack),
  'Crafted JS has right hash',
)
