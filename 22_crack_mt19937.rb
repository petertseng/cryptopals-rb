require_relative 'assert'
require_relative 'mt19937'

delay = rand(960) + 40

# Just simulating the passage of time.
seed = Time.now.to_i - delay

r = MT19937.new(seed)
v = r.rand

now = Time.now.to_i

seeds = (0..1000).map { |n| now - n }.select { |s| MT19937.new(s).rand == v }

assert_eq([seed], seeds)
