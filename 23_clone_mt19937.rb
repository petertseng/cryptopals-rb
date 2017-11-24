require_relative 'assert'
require_relative 'mt19937'

class Untemper < MT19937
  def self.untemper(x)
    x = unright(x, L, FULL_MASK)
    x = unleft(x, T, C)
    x = unleft(x, S, B)
    unright(x, U, D)
  end

  def self.unright(n, shift, nd)
    nbits = n.digits(2)
    ndbits = nd.digits(2)
    bits = nbits.dup
    (W - shift).times { |i|
      bits[W - 1 - shift - i] ^= 1 if (bits[W - 1 - i] || 0) & (ndbits[W - 1 - shift - i] || 0) != 0
    }
    bits.reverse.reduce(0) { |acc, bit| acc * 2 + bit }
  end

  def self.unleft(n, shift, nd)
    nbits = n.digits(2)
    ndbits = nd.digits(2)
    bits = nbits.dup
    (W - shift).times { |i|
      bits[shift + i] = (bits[shift + i] || 0) ^ 1 if (bits[i] || 0) & (ndbits[shift + i] || 0) != 0
    }
    # Since we may set values past the end of the array, nils will fill in,
    # instead of zeroes.
    bits.reverse.reduce(0) { |acc, bit| acc * 2 + (bit || 0) }
  end
end

assert_eq(
  b = 0b0000111100110011,
  Untemper.unright(b ^ ((b >> (shift = 8)) & (nd = 0b01010101)), shift, nd),
)

assert_eq(
  b = 0b0000111100110011,
  Untemper.unleft(b ^ ((b << (shift = 8)) & (nd = 0b0101010100000000)), shift, nd),
)

r = MT19937.new(19)
state = Array.new(MT19937::N) { Untemper.untemper(r.rand) }
r2 = MT19937.new(0)
r2.instance_variable_set('@x', state)

assert_eq(Array.new(l = MT19937::N * 2) { r.rand }, Array.new(l) { r2.rand })
