require_relative 'assert'
require_relative 'invmod'
require_relative 'mod_pow'
require_relative 'rsa'

secret = rand(2 ** 64)

cs_and_ns = 3.times.map {
  e, n = rsa_key(128).values_at(:public, :n)
  assert_eq(3, e, 'prereq for this attack: e = 3')
  [mod_pow(secret, e, n), n]
}

ns = cs_and_ns.map(&:last)

m_ss = 3.times.map { |i|
  (ns[0...i] + ns[(i + 1)..-1]).reduce(:*)
}

# I don't understand what the description means by
# "leave off the final modulus operation"
# It was necessary to mod by N_012 to get the answer.
# Unless they mean a different modulus???
result = cs_and_ns.zip(m_ss).map { |(c, n), m_s|
  c * m_s * invmod(m_s, n)
}.sum % ns.reduce(:*)

assert_eq(secret ** 3, result)
