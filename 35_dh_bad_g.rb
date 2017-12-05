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

def sender(p, proposed_g, message, rx, tx)
  a = rand(p - 2) + 2

  # Send params and A.
  tx.puts(p)
  tx.puts(proposed_g)

  # Receive the actual g back (this is what the ACK is for, right?)
  g = rx.readline.to_i

  a_pub = (g ** a) % p
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

  # We find this g acceptable always, ack it unchanged.
  tx.puts(g)

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

def middle(rxa, txa, rxb, txb, g_to_inject, derive_key, check)
  # Receive parameters.
  p = rxa.readline.to_i
  # Ignore g from a
  _ = rxa.readline

  # Send to B.
  txb.puts(p)
  txb.puts(g_to_inject[p])

  # Ignore g from b
  _ = rxb.readline
  # Send g to A.
  txa.puts(g_to_inject[p])

  # Read their keys and pass them on to each other.
  a_pub = rxa.readline.to_i
  txb.puts(a_pub)
  b_pub = rxb.readline.to_i
  txa.puts(b_pub)

  k = derive_key[p, a_pub, b_pub]

  m = receive_message(rxa, k)
  check[m]
  send_message(txb, k, m)

  m = receive_message(rxb, k)
  check[m]
  send_message(txa, k, m)
end

[
  # If g = 1, key is always 1.
  [->(_) { 1 }, ->(_, _, _) { key(1) }],
  # If g = p, key is always 0.
  [->(p) { p }, ->(_, _, _) { key(0) }],
  # If g = p - 1:
  # (p - 1) ** even % p = 1
  # (p - 1) ** odd  % p = p - 1
  # So, if I saw two p - 1 over the wire,
  # both private keys are odd, which means the secret is p - 1.
  # Otherwise, if we see a 1, the secret will be 1, obviously.
  [->(p) { p - 1 }, ->(p, a_pub, b_pub) {
    key(a_pub == p - 1 && b_pub == p - 1 ? p - 1 : 1)
  }],
].each { |g_to_inject, derive_key|
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
    middle(rxa, txam, rxb, txbm, g_to_inject, derive_key, ->(s) {
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
}
