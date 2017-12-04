# Raise base to the power of exp by squaring.
def mod_pow(base, exp, mod)
  return 1 if exp == 0

  odds = 1
  evens = base

  while exp >= 2
    odds = odds * evens % mod if exp.odd?
    evens = evens * evens % mod
    exp /= 2
  end

  evens * odds % mod
end
