require_relative 'assert'
require_relative 'mdpad'
require_relative 'sha1'

KEY = Array.new(rand(10) + 20) { rand(256) }.pack('c*').freeze

def good?(msg, mac)
  sha1(KEY + msg) == mac
end

original_message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'.freeze

original_hash = sha1(KEY + original_message)
# This should be obvious, but we'll do it anyway.
assert_eq(true, good?(original_message, original_hash))

string_to_add = ';admin=true'.freeze

# Extra requirement not noted on http://cryptopals.com/sets/4/challenges/29
# When we calculate the new hash,
# ordinarily the length at the end would say the message is short,
# but for the verifier to declare the concatenated message good,
# the length must say the message is longer.
#
# If not making this change, there is no way to forge a message that will validate.
# The author only determined this by printing out the message after sha1 had padded it,
# and noticing the difference between the calls that assign new_hash
# versus the calls that verify the forged message.
#
# Original message length > 64 (which is 512 / 8),
# so we need to add 512 * 2 to the length.
# Note that if the prefix were longer, we might have to add more!
# Further, if the prefix's possible length has a wide range of values,
# then we might have to consider multiple possibilities ([1, 2, 3].map { |x| x * 512 })
new_hash = sha1(string_to_add, original_hash.each_char.each_slice(8).map { |a| Integer(a.join, 16) }, 1024)

right_message = (0..128).map { |n|
  mdpad(?x * n + original_message, :big)[n..-1] + string_to_add
}.find { |s| good?(s, new_hash) }

assert_eq(false, right_message.nil?)
# We already ensure this through the `find` above, but whatever.
assert_eq(true, good?(right_message, new_hash))
