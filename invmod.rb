require_relative 'assert'

def gcd(a, b)
  r_minus_one = a
  s_minus_one = 1
  t_minus_one = 0
  r = b
  s = 0
  t = 1
  loop {
    q = r_minus_one / r
    r_plus_one = r_minus_one - q * r
    s_plus_one = s_minus_one - q * s
    t_plus_one = t_minus_one - q * t

    return [r, s, t] if r_plus_one == 0

    r_minus_one = r
    r = r_plus_one
    s_minus_one = s
    s = s_plus_one
    t_minus_one = t
    t = t_plus_one
  }
end

def invmod(a, m)
  must_be_one, x, _ = gcd(a, m)
  assert_eq(1, must_be_one, "#{a} and #{m} not coprime")
  assert_eq(1, (a * x) % m, "Inverting #{a} mod #{m} did not find an inverse, got #{x}")
  x % m
end
