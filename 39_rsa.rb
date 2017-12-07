require_relative 'assert'
require_relative 'invmod'
require_relative 'mod_pow'
require_relative 'rsa'

assert_eq(2753, invmod(17, 3120))

[32, 64, 128, 512].each { |bits|
  e, d, n = rsa_key(bits).values_at(:public, :private, :n)
  m = 42
  c = mod_pow(m, e, n)
  assert_eq(42, mod_pow(c, d, n), "roundtrip at #{bits} bits")
}
