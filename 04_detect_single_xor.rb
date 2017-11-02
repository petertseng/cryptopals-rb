require_relative 'assert'
require_relative 'hex'
require_relative 'xor'

candidates = File.read('data/04.txt').lines.map { |l| hex_to_bytes(l.strip) }

assert_eq(
  "Now that the party is jumping\n",
  detect(candidates),
)
