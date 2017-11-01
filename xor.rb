def xor(a, b)
  a.zip(b).map { |x, y| x ^ y }
end

def xor_repeating(a, b)
  xor(a, b * (1 + a.size / b.size))
end

def xor_single(a, b)
  xor(a, [b] * a.size)
end

# http://www.macfreek.nl/memory/Letter_Distribution
ENGLISH_FREQ = {
  ' ' => 0.18288462654132653,
  ?e => 0.10266650371711405,
  ?t => 0.07516998273511516,
  ?a => 0.06532167023346977,
  ?o => 0.06159577254159049,
  ?n => 0.05712011128985469,
  ?i => 0.05668443260048856,
  ?s => 0.05317005343812784,
  ?r => 0.04987908553231180,
  ?h => 0.04978563962655234,
  ?l => 0.03317547959533063,
  ?d => 0.03282923097335889,
  ?u => 0.02275795359120720,
  ?c => 0.02233675963832357,
  ?m => 0.02026567834113036,
  ?f => 0.01983067155219636,
  ?w => 0.01703893766467868,
  ?g => 0.01624904409178952,
  ?p => 0.01504324284647170,
  ?y => 0.01427666624127353,
  ?b => 0.01258880743014620,
  ?v => 0.00796116438442061,
  ?k => 0.00560962722644426,
  ?x => 0.00140920161949961,
  ?j => 0.00097521808184139,
  ?q => 0.00083675498119895,
  ?z => 0.00051284690692656,
}

def crack_single(bytes, must_be_printable: true)
  scores = (0...256).map { |i|
    candidate = xor_single(bytes, i)
    next [i, 1.0 / 0.0] if must_be_printable && !candidate.all? { |c|
      # Allow newlines
      c == 10 || (32..127).cover?(c)
    }
    str = candidate.pack('c*')
    lower_english_only = str.downcase.each_char.select { |c| c == ' ' || (?a..?z).cover?(c) }
    freqs = lower_english_only.group_by(&:itself).transform_values(&:size)
    [
      i,
      ENGLISH_FREQ.map { |letter, expect_freq|
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
