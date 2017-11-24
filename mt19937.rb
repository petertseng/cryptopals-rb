class MT19937
  W = 32
  N = 624
  M = 397
  R = 31
  A = 0x9908B0DF
  U = 11
  D = 0xFFFFFFFF
  S = 7
  B = 0x9D2C5680
  T = 15
  C = 0xEFC60000
  L = 18

  F = 1812433253

  FULL_MASK = (1 << W) - 1
  LOW_MASK = (1 << R) - 1
  HIGH_MASK = (1 << (W - R)) - 1 << R

  def initialize(seed)
    @x = Array.new(N)
    @x[0] = seed
    (1...N).each { |i|
      @x[i] = (F * (@x[i - 1] ^ (@x[i - 1] >> W - 2)) + i) & FULL_MASK
    }
  end

  def rand
    y = (@x[M] ^ a(@x[0] & HIGH_MASK | @x[1] & LOW_MASK)) & FULL_MASK
    @x.shift
    @x << y
    y ^= (y >> U) & D
    y ^= (y << S) & B
    y ^= (y << T) & C
    y ^ (y >> L)
  end

  def a(x)
    (x >> 1) ^ (x.even? ? 0 : A)
  end
end
