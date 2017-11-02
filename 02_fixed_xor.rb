require_relative 'assert'
require_relative 'hex'
require_relative 'xor'

assert_eq(
  '746865206b696420646f6e277420706c6179',
  bytes_to_hex(xor(hex_to_bytes('1c0111001f010100061a024b53535009181c'), hex_to_bytes('686974207468652062756c6c277320657965'))),
)
