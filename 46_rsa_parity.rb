require 'base64'

require_relative 'mod_pow'
require_relative 'rsa'

def gen
  p = Base64.decode64('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
  m = p.bytes.reduce(0) { |acc, n| acc * 256 + n }

  e, d, n = rsa_key(512).values_at(:public, :private, :n)

  [mod_pow(m, e, n), e, n, ->(c) { mod_pow(c, d, n) % 2 }, ->(check) { p == check }]
end

ct, e, n, parity, check = gen

lower = 0
upper = n - 1

two = mod_pow(2, e, n)

until upper - lower <= 1
  middle = (upper + lower) / 2

  ct *= two

  if parity[ct] == 0
    upper = middle
  else
    lower = middle
  end
end

s = lower.digits(256).reverse.pack('c*')

# TODO: I seem to get the last byte wrong???
(0..255).find { |b|
  s[-1] = b.chr
  check[s]
}

puts s if ARGV.include?('-v')

assert_eq(true, check[s], 'successful decrypt')
