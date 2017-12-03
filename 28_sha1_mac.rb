require 'digest/sha1'

require_relative 'assert'
require_relative 'sha1'

s = ''

512.times {
  s << ?a
  assert_eq(Digest::SHA1::hexdigest(s), sha1(s), s)
}
