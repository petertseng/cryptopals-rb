require 'base64'
require 'openssl'

bytes = Base64.decode64(File.read('data/07.txt'))
cipher = OpenSSL::Cipher::AES.new(128, :ECB).decrypt
cipher.key = 'YELLOW SUBMARINE'
puts cipher.update(bytes) if ARGV.include?('-v')
