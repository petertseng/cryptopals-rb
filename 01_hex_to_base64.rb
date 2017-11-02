require 'base64'
require_relative 'assert'
require_relative 'hex'

# Set 1 Challenge 1: hex_to_base64
def hex_to_base64(s)
  Base64.strict_encode64(hex_to_bytes(s).pack('c*'))
end

assert_eq(
  'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t',
  hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'),
)
