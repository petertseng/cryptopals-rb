require 'base64'
require 'digest'
require 'openssl'

require_relative 'srp'

module SRP
  def self.client(rx, tx)
    a = rand(N - 2) + 2
    a_pub = mod_pow(G, a, N)

    tx.puts(I)
    tx.puts(a_pub)

    salt = rx.read(SALT_LEN)
    b_pub = rx.readline.to_i

    u = Digest::SHA256.hexdigest((a_pub * N + b_pub).to_s).to_i(16)

    x = Digest::SHA256.hexdigest(salt + P).to_i(16)
    s = mod_pow(b_pub - K * mod_pow(G, x, N), a + u * x, N)
    k = Digest::SHA256.hexdigest(s.to_s)

    hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k, salt)

    tx.puts(Base64.encode64(hmac))
  end
end

Thread.abort_on_exception = true

rxa, txa = IO.pipe
rxb, txb = IO.pipe

a = Thread.new {
  SRP::client(rxb, txa)
}
b = Thread.new {
  SRP::server(rxa, txb)
}
a.join
b.join
