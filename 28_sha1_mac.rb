require 'digest/sha1'

require_relative 'assert'
require_relative 'sha1'

s = ''

512.times {
  s << ?a
  assert_eq(Digest::SHA1::hexdigest(s), sha1(s), s)
}

key = Array.new(16) { rand(256) }.pack('c*').freeze

message = 'hello'
mac = sha1(key + message)

assert_eq(false, mac == sha1(key + 'jello'))
