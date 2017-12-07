require 'openssl'

require_relative 'invmod'

def rsa_key(bits)
  p = OpenSSL::BN.generate_prime(bits).to_i
  q = OpenSSL::BN.generate_prime(bits).to_i
  n = p * q
  et = (p - 1) * (q - 1)
  e = 3
  d = invmod(e, et)
  {
    public: e,
    private: d,
    n: n,
  }
end
