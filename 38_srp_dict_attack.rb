require 'base64'
require 'digest'
require 'openssl'

require_relative 'assert'
require_relative 'mod_pow'

module SimpleSRP
  N = 17676318486848893030961583018778670610489016512983351739677143
  G = 2
  K = 3
  I = 'user@email.com'.freeze
  POSSIBLE_PASSWORDS = Array.new(1000) {
    Array.new(40) { rand(256) }.pack('c*').freeze
  }.freeze
  P = POSSIBLE_PASSWORDS.sample
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
    b_pub = mod_pow(G, b, N)
    u = rand(2 ** 128)

    tx.write(salt)
    tx.puts(b_pub)
    tx.puts(u)

    s = mod_pow(a_pub * mod_pow(v, u, N), b, N)
    k = Digest::SHA256.hexdigest(s.to_s)

    want = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k, salt)
    got = Base64.decode64(rx.readline)

    assert_eq(want, got)
  end

  def self.client(rx, tx)
    a = rand(N - 2) + 2
    a_pub = mod_pow(G, a, N)

    tx.puts(I)
    tx.puts(a_pub)

    salt = rx.read(SALT_LEN)
    b_pub = rx.readline.to_i
    u = rx.readline.to_i

    x = Digest::SHA256.hexdigest(salt + P).to_i(16)
    s = mod_pow(b_pub, a + u * x, N)
    k = Digest::SHA256.hexdigest(s.to_s)

    hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k, salt)

    tx.puts(Base64.encode64(hmac))
  end
end

Thread.abort_on_exception = true

rxa, txa = IO.pipe
rxb, txb = IO.pipe

a = Thread.new {
  SimpleSRP::client(rxb, txa)
}
b = Thread.new {
  SimpleSRP::server(rxa, txb)
}
a.join
b.join

module SimpleSRP
  def self.attacker(rx, tx)
    salt = Array.new(SALT_LEN) { rand(256) }.pack('c*')
    # v is based on x, which is based on P, so there is no value we can use.
    v = rand(N - 2) + 2

    # It doesn't appear that server uses I...
    _ = rx.readline
    a_pub = rx.readline.to_i

    b = rand(N - 2) + 2
    b_pub = mod_pow(G, b, N)
    u = rand(2 ** 128)

    tx.write(salt)
    tx.puts(b_pub)
    tx.puts(u)

    got = Base64.decode64(rx.readline)
    sha256 = OpenSSL::Digest.new('sha256')

    passwords = POSSIBLE_PASSWORDS.select { |p|
      x = Digest::SHA256.hexdigest(salt + p).to_i(16)
      v = mod_pow(G, x, N)
      s = mod_pow(a_pub * mod_pow(v, u, N), b, N)
      k = Digest::SHA256.hexdigest(s.to_s)
      hmac = OpenSSL::HMAC.digest(sha256, k, salt)
      hmac == got
    }

    assert_eq(true, passwords.include?(P), "Find the correct password #{P}, found #{passwords}")
  end
end

rxa, txa = IO.pipe
rxb, txb = IO.pipe

a = Thread.new {
  SimpleSRP::client(rxb, txa)
}
b = Thread.new {
  SimpleSRP::attacker(rxa, txb)
}
a.join
b.join
