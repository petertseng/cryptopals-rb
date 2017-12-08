require 'digest'

require_relative 'invmod'
require_relative 'mod_pow'

def sign(p:, q:, g:, x:, m:, k: nil)
  loop {
    k ||= rand(q - 2) + 2
    r = mod_pow(g, k, p) % q
    next if r == 0
    h = Digest::SHA1.hexdigest(m).to_i(16)
    s = (invmod(k, q) * (h + x * r)) % q
    next if s == 0
    return [r, s]
  }
end

def verify?(g:, p:, q:, r:, s:, y:, m:)
  return false unless (1...q).cover?(r)
  return false unless (1...q).cover?(s)
  w = invmod(s, q)
  h = Digest::SHA1.hexdigest(m).to_i(16)
  u1 = (h * w) % q
  u2 = (r * w) % q
  v = ((mod_pow(g, u1, p) * mod_pow(y, u2, p)) % p) % q
  v == r
end

def private_key(r:, s:, k:, q:, m:)
  (s * k - Digest::SHA1.hexdigest(m).to_i(16)) * invmod(r, q) % q
end
