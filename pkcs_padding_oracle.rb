def gen(bit_size, verbose: false)
  byte_size = bit_size / 8

  e, d, n = rsa_key(bit_size / 2).values_at(:public, :private, :n)
  data_block = Array.new(byte_size / 2) { rand(256) }
  bytes = [0, 2] + ([255] * (byte_size - 3 - data_block.size)) + [0] + data_block
  m = bytes.reduce(0) { |acc, b| acc * 256 + b }

  if verbose
    puts m
    puts m.to_s(16)
  end

  [mod_pow(m, e, n), e, n, ->(c) {
    bytes = mod_pow(c, d, n).digits(256)
    bytes.size == byte_size - 1 && bytes[-1] == 2
  }, ->(check) { m == check }, ->(check) { assert_eq(m, check, 'Decrypt') }]
end

def crack(ct, e, n, bit_size, oracle, verbose: false)
  two_b = 2 << (bit_size - 16)
  three_b = 3 << (bit_size - 16)

  s = [1]
  m = [
    [
      [two_b, three_b - 1],
    ]
  ]

  1.step { |i|
    if i == 1
      # Step 2a
      s << (n / three_b).step.find { |s_cand|
        oracle[(ct * mod_pow(s_cand, e, n)) % n]
      }
    elsif m[-1].size > 1
      # Step 2b
      # Can't use step directly, it seems to convert to float for large numbers.
      s << 1.step.find { |delta|
        s_cand = s[-1] + delta
        oracle[(ct * mod_pow(s_cand, e, n)) % n]
      } + s[-1]
    else
      # Step 2c
      a, b = m[-1][0]
      # Can't use step directly, it seems to convert to float for large numbers.
      base = 2 * (b * s[-1] - two_b) / n
      s << 0.step { |delta|
        r = base + delta
        s_min = (two_b + r * n) / b
        s_max = (three_b + r * n) / a
        good_s = (s_min..s_max).find { |s_cand|
          oracle[(ct * mod_pow(s_cand, e, n)) % n]
        }
        break good_s if good_s
      }
    end
    puts "#{Time.now} s#{i}: #{s[-1]}" if verbose

    # Step 3
    m << m[-1].flat_map { |aa, bb|
      # This needs to be a ceil not a floor, because of <= on the lower bound.
      # Can't use to_f (precision), so simulate ceil by adding divisor - 1
      r_min = (aa * s[-1] - three_b + 1 + n - 1) / n
      r_max = (bb * s[-1] - two_b) / n
      (r_min..r_max).map { |r|
        # Can't use to_f (precision), so simulate ceil by adding divisor - 1
        min = [aa, (two_b + r * n + s[-1] - 1) / s[-1]].max
        max = [bb, (three_b - 1 + r * n) / s[-1]].min
        [min, max]
      }
    }.reject { |l| l.size == 0 }

    len = m[-1].map { |aa, bb| bb - aa + 1 }
    puts "m#{i} has #{m[-1].size} intervals with #{len} len" if verbose
    # Our s[0] is just 1, so we can just take m[-1][0][0]
    # (The beginning of the first and only interval of the last iteration)
    return m[-1][0][0] if len.sum == 1
  }
end
