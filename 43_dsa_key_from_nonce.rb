require 'digest'

require_relative 'dsa'
require_relative 'mod_pow'

p = <<P.split.join.to_i(16)
800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1
P

q = 'f4f47f05794b256174bba6e9b396a7707e563c5b'.to_i(16)

g = <<G.split.join.to_i(16)
5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
0f5b64c36b625a097f1651fe775323556fe00b3608c887892
878480e99041be601a62166ca6894bdd41a7054ec89f756ba
9fc95302291
G

10.times {
  k = rand(q - 2) + 2
  m = Array.new(16) { rand(256) }.pack('c*').freeze
  x = rand(2 ** 32)
  y = mod_pow(g, x, p)
  r, s = sign(p: p, q: q, g: g, x: x, m: m, k: k)
  assert_eq(x, private_key(r: r, s: s, k: k, q: q, m: m))
  assert_eq(true, verify?(g: g, p: p, q: q, r: r, s: s, y: y, m: m))
}

y = <<Y.split.join.to_i(16)
84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
bb283e6633451e535c45513b2d33c99ea17
Y

m = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940

# This takes a little more than a minute.
possible_keys = (0..(2 ** 16)).map { |k|
  private_key(r: r, s: s, k: k, q: q, m: m)
}.select { |x|
  y == mod_pow(g, x, p)
}

assert_eq(false, possible_keys.empty?, 'finding a possible key')
assert_eq(true, possible_keys.any? { |x| Digest::SHA1.hexdigest(x.to_s(16)) == '0954edd5e0afe5542a4adf012611a91912a3ec16' })
