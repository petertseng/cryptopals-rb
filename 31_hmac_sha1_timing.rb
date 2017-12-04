require_relative 'assert'
require_relative 'hmac'

assert_eq('fbdb1d1b18aa6c08324b7d64b71fb76370690e1d', hmac_sha1('', ''))
assert_eq('de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9', hmac_sha1('key', 'The quick brown fox jumps over the lazy dog'))
