def xor(a, b)
  a.zip(b).map { |x, y| x ^ y }
end

def xor_repeating(a, b)
  xor(a, b * (1 + a.size / b.size))
end

def xor_single(a, b)
  xor(a, [b] * a.size)
end

ENGLISH_FREQ = [
  0.08167,
  0.01492,
  0.02782,
  0.04253,
  0.12702,
  0.02228,
  0.02015,
  0.06094,
  0.06966,
  0.00153,
  0.00772,
  0.04025,
  0.02406,
  0.06749,
  0.07507,
  0.01929,
  0.00095,
  0.05987,
  0.06327,
  0.09056,
  0.02758,
  0.00978,
  0.02361,
  0.00150,
  0.01974,
  0.00074,
].freeze

def crack_single(bytes, must_be_printable: true)
  scores = (0...256).map { |i|
    candidate = xor_single(bytes, i)
    next [i, 1.0 / 0.0] if must_be_printable && !candidate.all? { |c|
      # Allow newlines
      c == 10 || (32..127).cover?(c)
    }
    str = candidate.pack('c*')
    lower_english_only = str.downcase.each_char.select { |c| (?a..?z).cover?(c) }
    freqs = lower_english_only.group_by(&:itself).transform_values(&:size)
    [
      i,
      ENGLISH_FREQ.zip(?a..?z).map { |expect_freq, letter|
        got_freq = (freqs[letter]&.to_f &./ lower_english_only.size) || 0
        (expect_freq - got_freq).abs
      }.sum
    ]
  }

  best_byte, best_score = scores.min_by(&:last)

  best_score.finite? ? [best_byte, xor_single(bytes, best_byte), best_score] : nil
end

def detect(candidates)
  best = candidates.map { |c|
    crack_single(c, must_be_printable: true)
  }.compact.min_by(&:last)
  best[1].pack('c*')
end

BITS = (0...256).map { |x| x.to_s(2).count(?1) }.freeze

def hamming_distance(a, b)
  a.zip(b).map { |x, y| BITS[x ^ y] }.sum
end
