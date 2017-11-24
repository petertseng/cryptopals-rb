require_relative 'assert'
require_relative 'mt19937'

# I have no idea whether these values are right though?
# This is just whatever my code happened to output,
# so this is only testing that I didn't change the behaviour
# (whether that behaviour is right or wrong)
r = MT19937.new(19)
assert_eq([418903645, 1848846958, 3269542645, 1772717410, 1060590504], Array.new(5) { r.rand })
