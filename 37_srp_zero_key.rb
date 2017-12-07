require 'base64'
require 'digest'
require 'openssl'

require_relative 'srp'

module SRP
  def self.bad_client(rx, tx, a_pub)
    tx.puts(I)
    tx.puts(a_pub)

    salt = rx.read(SALT_LEN)
    # Ignore b_pub
    _ = rx.readline.to_i

    k = Digest::SHA256.hexdigest(?0)

    hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k, salt)

    tx.puts(Base64.encode64(hmac))
  end
end

Thread.abort_on_exception = true

rxa, txa = IO.pipe
rxb, txb = IO.pipe

[0, SRP::N, SRP::N * 2].each { |bad_a_pub|
  a = Thread.new {
    SRP::bad_client(rxb, txa, bad_a_pub)
  }
  b = Thread.new {
    SRP::server(rxa, txb)
  }
  a.join
  b.join
}
