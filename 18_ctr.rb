require 'base64'

require_relative 'aes_ctr'
require_relative 'assert'

c = Base64.decode64('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')

p = ctr(c.bytes, key: 'YELLOW SUBMARINE', nonce: 0).pack('c*')

assert_eq("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", p)
