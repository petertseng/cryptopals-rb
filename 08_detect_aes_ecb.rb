require 'openssl'

require_relative 'assert'
require_relative 'hex'

candidates = File.read('data/08.txt').lines.map { |l| hex_to_bytes(l.strip) }
ecb_lines = candidates.each_with_index.select { |c, i|
  c.each_slice(16).group_by(&:itself).transform_values(&:size).values.max > 1
}.map(&:last)

assert_eq([132], ecb_lines)
