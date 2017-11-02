require 'base64'

require_relative 'aes_cbc'
require_relative 'assert'
require_relative 'xor'

bytes = Base64.decode64(File.read('data/10.txt')).bytes
puts aes_cbc_decrypt(bytes, key: 'YELLOW SUBMARINE', iv: [0] * 16).pack('c*') if ARGV.include?('-v')
