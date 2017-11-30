require_relative 'assert'
require_relative 'mt19937'

# I have no idea whether these values are right though?
# Uses test values from: https://github.com/cslarsen/mersenne-twister/blob/master/test-mt.cpp
# So if my code is wrong, it is no more wrong than that code.
r = MT19937.new(1)
assert_eq(
  [
    1791095845, 4282876139, 3093770124, 4005303368, 491263, 550290313,
    1298508491, 4290846341, 630311759, 1013994432, 396591248, 1703301249,
  ],
  Array.new(12) { r.rand },
)
