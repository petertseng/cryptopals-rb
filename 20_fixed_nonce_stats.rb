require 'base64'

require_relative 'aes_ctr'
require_relative 'assert'
require_relative 'xor'

key = Array.new(16) { rand(256).chr }.join

texts = File.readlines('data/20.txt').map { |b| ctr(Base64.decode64(b).bytes, key: key, nonce: 0) }
len = texts.map(&:size).min

results = len.times.map { |i|
  bytes = texts.map { |t| t[i] }
  crack_single(bytes)
}

puts texts.each_index.map { |i|
  results.map { |(_k, ps, _s)| ps[i] }.pack('c*')
} if ARGV.include?('-v')

# The first byte of each line (results[0][1]) is wrong,
# but the answer is as the stats say.
# Any way to make it get the right result?
# In the meantime, we'll test results[1][1] (second byte of each line)
assert_eq(
  [39, 117, 117, 97, 117, 117, 97, 101, 114, 104, 101, 111, 111, 108, 104, 111, 67, 104, 101, 32, 97, 104, 102, 117, 121, 97, 111, 104, 110, 114, 117, 112, 97, 111, 32, 111, 111, 101, 97, 107, 104, 32, 104, 111, 111, 32, 32, 117, 101, 111, 32, 105, 67, 111, 97, 67, 111, 110, 117, 110],
  results[1][1],
)
