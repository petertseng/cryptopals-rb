require_relative 'assert'
require_relative 'invmod'
require_relative 'mod_pow'
require_relative 'rsa'

secret = rand(2 ** 128)

e, d, n = rsa_key(256).values_at(:public, :private, :n)
c = mod_pow(secret, e, n)

s = rand(n - 2) + 2
c_prime = (c * mod_pow(s, e, n)) % n

p_prime = mod_pow(c_prime, d, n)

recovered_p = (p_prime * invmod(s, n)) % n

assert_eq(secret, recovered_p)
