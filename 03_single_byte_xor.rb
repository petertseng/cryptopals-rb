require_relative 'assert'
require_relative 'hex'
require_relative 'xor'

assert_eq(
  'Cooking MC\'s like a pound of bacon',
  crack_single(
    hex_to_bytes('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'),
    must_be_printable: true,
  )[1].pack('c*'),
)
