require_relative 'assert'
require_relative 'mod_pow'

def pair(p, g)
  [(priv = rand(p)), mod_pow(g, priv, p)]
end

def dh(p, g)
  a_priv, a_pub = pair(p, g)
  b_priv, b_pub = pair(p, g)

  assert_eq(mod_pow(b_pub, a_priv, p), mod_pow(a_pub, b_priv, p))
end

dh(37, 5)

p = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff'.split.join.to_i(16)

dh(p, 2)
