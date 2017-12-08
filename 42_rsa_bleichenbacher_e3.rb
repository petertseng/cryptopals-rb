require 'digest'

require_relative 'assert'
require_relative 'mod_pow'
require_relative 'rsa'

# 512 is not large enough to have room to cube, but 1024 is just barely.
BIT_SIZE = 1024
BYTE_SIZE = BIT_SIZE / 8

def asn1(sha1)
  # https://stackoverflow.com/a/3715736
  [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x20] + sha1
end

def good_sig?(m, sig, e, n, vulnerable: false)
  expected_data = asn1(Digest::SHA1.digest(m).bytes).freeze

  bytes = mod_pow(sig, e, n).digits(256)
  bytes.concat([0] * (BYTE_SIZE - bytes.size))
  bytes.reverse!
  bytes.freeze

  return false if bytes[0] != 0
  return false if bytes[1] != 1
  # Where's the next zero?
  second_zero = bytes[1..-1].index(0) &.+ 1
  return false if second_zero.nil?
  return false if !vulnerable && second_zero != BYTE_SIZE - 1 - expected_data.size
  # Note that the vulnerable version even accepts zero instances of 255...
  return false unless (2...second_zero).all? { |i| bytes[i] == 255 }

  expected_data == bytes[(second_zero + 1), expected_data.size]
end

e, d, n = rsa_key(BIT_SIZE / 2).values_at(:public, :private, :n)
assert_eq(3, e, 'prereq for this attack: e = 3')

m = 'hi mom!'.freeze
asn1_data = asn1(Digest::SHA1.digest(m).bytes).freeze

# Not sure if I have the endianness right here. Front of block = least significant.
#bytes = hash.reverse + [0] + [255] * (BYTE_SIZE - 3 - hash.size) + [1, 0]
# Never mind, we'll do front of block = most significant.
# This seems sensible because the rationale for the 0 at the start
# is so that the resulting number < N.
bytes = [0, 1] + [255] * (BYTE_SIZE - 3 - asn1_data.size) + [0] + asn1_data
asn1_block = bytes.reduce(0) { |acc, b| acc * 256 + b }
assert_eq(true, asn1_block < n, "ASN.1 #{asn1_block} < N #{n}")

sig = mod_pow(asn1_block, d, n)

assert_eq(true, good_sig?(m, sig, e, n), 'non-vulnerable can accept good sig')
assert_eq(true, good_sig?(m, sig, e, n, vulnerable: true), 'vulnerable can accept good sig')

def forge(asn1_data)
  # https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html
  # 36 bytes: 20 for the sha1 hash, 15 for asn1 data, 1 for the 00.
  # 36 bytes * 8 bits/byte = 288 bits.
  # This n is indeed divisible by 3.
  #n = 2**288 - Digest::SHA1.hexdigest(m).to_i(16)
  # For 3072 bits and signature placed at 2072 bits:
  # 2^3057 - 2^2360 + D * 2^2072 + garbage
  # 3057 is 3072 - 16 + 1, because of the leading 0, 1 bytes.
  # 2360 is 2072 + 288
  # Now we can use 2^1019 - (N * 2^34 / 3)
  # So that's where the bit size was divisible by 3, what if it's not?
  # Therefore, I'll try to make this work without.

  # I'll arbitrarily choose 4 as the number of 255 bytes I add,
  # but any number will do, as long as I can find a cube root.
  target_bytes = [0, 1] + [255] * 4 + [0] + asn1_data
  target_bytes.concat([0] * (BYTE_SIZE - target_bytes.size))
  target_value = target_bytes.reduce(0) { |acc, b| acc * 256 + b }
  # Use the next largest cube root.
  # Its cube will be target_value plus some garbage at the end.
  # Don't use ** (1.0 / 3.0) since it's not precise enough.
  (1..(target_value ** (1.0 / 3.0).ceil)).bsearch { |x|
    x ** 3 > target_value
  } + 1
end

forged = forge(asn1_data)
assert_eq(false, good_sig?(m, forged, e, n), 'non-vulnerable knows to reject forged sig')
assert_eq(true, good_sig?(m, forged, e, n, vulnerable: true), 'vulnerable accepts forged sig')
