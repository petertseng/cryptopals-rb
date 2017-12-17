require_relative 'assert'
require_relative 'mod_pow'
require_relative 'pkcs_padding_oracle'
require_relative 'rsa'

BIT_SIZE = 256
VERBOSE = ARGV.delete('-v')

ct, e, n, oracle, check, strict_check = gen(BIT_SIZE, verbose: VERBOSE)
assert_eq(true, oracle[ct], 'oracle accepts unaltered ciphertext')
assert_eq(false, check[ct], 'ciphertext is not the answer')

ans = crack(ct, e, n, BIT_SIZE, oracle, verbose: VERBOSE)
if VERBOSE
  puts ans
  puts ans.to_s(16)
end
strict_check[ans]
