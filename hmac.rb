require_relative 'sha1'
require_relative 'xor'

def hmac_sha1(key, message)
  key = sha1(key) if key.size > 64
  key = key.ljust(64, "\0").bytes.freeze
  outer = xor_single(key, 0x5c).pack('c*').freeze
  inner = xor_single(key, 0x36).pack('c*').freeze
  sha1(outer + [sha1(inner + message)].pack('H*'))
end
