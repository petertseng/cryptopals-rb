require_relative 'aes_cbc'
require_relative 'assert'
require_relative 'sha1'

def key(secret)
  [sha1(secret.digits(256).pack('c*'))].pack('H*')[0, 16]
end

def send_message(tx, k, message)
  iv = Array.new(16) { rand(256) }.freeze
  ct = aes_cbc_encrypt(message.bytes, key: k, iv: iv)
  tx.puts(ct.size)
  tx.write(ct.pack('c*'))
  tx.write(iv.pack('c*'))
end

def receive_message(rx, k)
  size = rx.readline.to_i
  ct = rx.read(size).bytes
  iv = rx.read(16).bytes
  aes_cbc_decrypt(ct, key: k, iv: iv).pack('c*')
end

def sender(p, g, message, rx, tx)
  a = rand(p - 2) + 2
  a_pub = (g ** a) % p

  # Send params and A.
  tx.puts(p)
  tx.puts(g)
  tx.puts(a_pub)

  # Receive B.
  b_pub = rx.readline.to_i

  s = (b_pub ** a) % p
  k = key(s)

  send_message(tx, k, message)
  received = receive_message(rx, k)

  assert_eq(message, received)
end

def echo(rx, tx)
  # Receive params and A.
  p = rx.readline.to_i
  g = rx.readline.to_i
  a_pub = rx.readline.to_i

  b = rand(p - 2) + 2
  b_pub = (g ** b) % p

  # Send B.
  tx.puts(b_pub)

  s = (a_pub ** b) % p
  k = key(s)

  received = receive_message(rx, k)
  send_message(tx, k, received)
end

Thread.abort_on_exception = true

rxa, txa = IO.pipe
rxb, txb = IO.pipe

message = Array.new(32) { rand(256) }.pack('c*').freeze

a = Thread.new {
  sender(563, 5, message, rxb, txa)
}
b = Thread.new {
  echo(rxa, txb)
}
a.join
b.join

def middle(rxa, txa, rxb, txb, check)
  # Receive parameters.
  p = rxa.readline.to_i
  g = rxa.readline.to_i
  # ignore a_pub
  _ = rxa.readline.to_i

  # Send to B.
  txb.puts(p)
  txb.puts(g)
  # If B were smart, B would balk.
  # P is definitely not a valid public key.
  txb.puts(p)

  # ignore b_pub
  _ = rxb.readline
  # If A were smart, A would balk.
  txa.puts(p)

  # Both parties computed (p ** x) % p, which is 0,
  # so both parties are using the key of 0.
  k = key(0)

  m = receive_message(rxa, k)
  check[m]
  send_message(txb, k, m)

  m = receive_message(rxb, k)
  check[m]
  send_message(txa, k, m)
end

message = Array.new(32) { rand(256) }.pack('c*').freeze

rxa, txa = IO.pipe
rxb, txb = IO.pipe
rxam, txam = IO.pipe
rxbm, txbm = IO.pipe

a = Thread.new {
  sender(563, 5, message, rxam, txa)
}
b = Thread.new {
  echo(rxbm, txb)
}
m = Thread.new {
  middle(rxa, txam, rxb, txbm, ->(s) {
    assert_eq(message, s, 'middle decrypt')
  })
}
a.join
b.join
m.join

# If the script finishes executing, M successfully stole the messages,
# with nobody the wiser.
# If M failed to steal, M would have raised on calling the check function.
# If the message got messed up when sending to A, A would have raised.
