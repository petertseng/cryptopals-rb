require_relative 'assert'
require_relative 'hex'

def pkcs7(bytes, len)
  raise "Impossible to pad #{bytes.size} to #{len}" if bytes.size > len
  diff = len - bytes.size
  bytes + [diff] * diff
end

assert_eq(
  'YELLOW SUBMARINE'.bytes + [4, 4, 4, 4],
  pkcs7('YELLOW SUBMARINE'.bytes, 20),
)
