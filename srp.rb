require 'base64'
# I that we are using a library for SHA256 since we only implemented SHA1.
require 'digest'
require 'openssl'

require_relative 'assert'
require_relative 'mod_pow'

module SRP
  N = 17676318486848893030961583018778670610489016512983351739677143
  G = 2
  K = 3
  I = 'user@email.com'.freeze
  P = Array.new(40) { rand(256) }.pack('c*').freeze
  SALT_LEN = 16

  def self.server(rx, tx)
    salt = Array.new(SALT_LEN) { rand(256) }.pack('c*')
    x = Digest::SHA256.hexdigest(salt + P).to_i(16)
    v = mod_pow(G, x, N)
    # Well, it says to save everything except x, so
    x = nil

    # It doesn't appear that server uses I...
    _ = rx.readline
    a_pub = rx.readline.to_i

    b = rand(N - 2) + 2
    b_pub = (K * v + mod_pow(G, b, N)) % N

    tx.write(salt)
    tx.puts(b_pub)

    u = Digest::SHA256.hexdigest((a_pub * N + b_pub).to_s).to_i(16)

    s = mod_pow(a_pub * mod_pow(v, u, N), b, N)
    k = Digest::SHA256.hexdigest(s.to_s)

    want = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k, salt)
    got = Base64.decode64(rx.readline)

    assert_eq(want, got)
  end
end
