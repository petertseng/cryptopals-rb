require 'net/http'

require_relative 'timing_attack'

# It was observed that on problem 31:
# delay at 3 ms per byte still revealed the key
# delay at 2 ms per byte sometimes still did
# delay at 1 ms per byte usually did not
# So we'll run this at 1 ms per byte,
# and detect differences by checking 10 times.

if ARGV.include?('--yes')
  puts timing_attack(10)
else
  puts 'Takes too long (around 2.5 minutes), pass --yes flag'
end
