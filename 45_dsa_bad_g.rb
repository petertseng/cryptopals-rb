require 'digest'

require_relative 'dsa'

p = <<P.split.join.to_i(16)
800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1
P

q = 'f4f47f05794b256174bba6e9b396a7707e563c5b'.to_i(16)

0.times {
  m = Array.new(16) { rand(256) }.pack('c*').freeze
  g = 0
  x = rand(2 ** 32)
  y = mod_pow(g, x, p)
  # This won't work; sign specifically rejects if r == 0
  # Will just run forever.
  # If it did work, it would produce r = 0.
  r, _ = sign(p: p, q: q, g: g, x: x, m: m)
  assert_eq(0, r)
  # It won't verify because verify explicitly rejects zeroes.
  # But if it didn't reject zeroes, it would accept the zero signature
  # for any message.
  assert_eq(true, verify?(g: g, p: p, q: q, r: r, s: s, y: y, m: m))
}

g = p + 1
10.times {
  x = rand(2 ** 32)
  y = mod_pow(g, x, p)

  z = rand(2 ** 32)
  r = mod_pow(y, z, p) % q
  s = (r * invmod(z, q)) % q
  10.times {
    m = Array.new(16) { rand(256) }.pack('c*').freeze
    assert_eq(true, verify?(g: g, p: p, q: q, r: r, s: s, y: y, m: m))
  }
}
