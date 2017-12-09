require_relative 'dsa'
require_relative 'invmod'

q = 'f4f47f05794b256174bba6e9b396a7707e563c5b'.to_i(16)

messages_by_r = File.readlines('data/44.txt').each_slice(4).map { |msg, s, r, m|
  [msg.split(': ')[1].chomp, s.split(?:)[1].to_i, r.split(?:)[1].to_i, m.split(?:)[1].to_i(16)]
}.group_by { |_, _, r, _| r }

pairs = messages_by_r.values.select { |x| x.size > 1 }

# we only need to take any arbitrary pair.
(msg, s1, r, m1), (_, s2, _, m2) = pairs.first

k = (((m1 - m2) % q) * invmod((s1 - s2) % q, q)) % q
private_key = private_key(r: r, s: s1, k: k, q: q, m: msg)

assert_eq('ca8f6f7c66fa362d40760d135b763eb8527d3d52', Digest::SHA1.hexdigest(private_key.to_s(16)))
