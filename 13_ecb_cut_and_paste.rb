require 'openssl'

require_relative 'assert'

def parse(query_string)
  query_string.split(?&).map { |x| x.split(?=) }.to_h
end

def profile_for(email)
  "email=#{email.tr('&=', '')}&uid=10&role=user"
end

KEY = Array.new(16) { rand(256) }.pack('c*').freeze

def encrypt(profile)
  cipher = OpenSSL::Cipher::AES.new(128, :ECB).encrypt
  cipher.key = KEY
  (cipher.update(profile) + cipher.final).bytes
end

def decrypt(bytes)
  cipher = OpenSSL::Cipher::AES.new(128, :ECB).decrypt
  cipher.key = KEY
  parse(cipher.update(bytes.pack('c*')) + cipher.final)
end

# email= is 6 chars.
# So let's ask for a profile that becomes:
# email=0000000000admin___________
#                 ^               ^
# arrows point to 16-byte boundaries
message = [0] * 10 + 'admin'.bytes + [11] * 11
# now we know what a PKCS#7-padded block that contains only "admin" looks like.
admin = encrypt(profile_for(message.pack('c*')))[16, 16]

# &uid=10&role= is 13 chars.
# If email is 13 chars, we will have the role at a boundary.
# email=xxxxxxxxxxxxx&uid=10&role=
#                 ^               ^
my_profile = encrypt(profile_for('user@user.com'))

# At this point, we can combine those two messages to get my profile as an admin.
assert_eq('admin', decrypt(my_profile[0, 32] + admin).fetch('role'))
