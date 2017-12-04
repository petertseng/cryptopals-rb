def timing_attack(shots = 1)
  hex = ((?0..?9).to_a + (?a..?f).to_a).map(&:freeze).freeze
  known = ''
  loop {
    known << hex.max_by { |d|
      sig = known + d
      uri = URI("http://localhost:8080/?file=foo&signature=#{sig}")
      t = Time.now
      return sig if Net::HTTP.get_response(uri).code == '200'
      (shots - 1).times { Net::HTTP.get_response(uri) }
      Time.now - t
    }
    puts '%s %2d %s' % [Time.now, known.size, known]
    raise 'Still not getting it?' if known.size >= 42
  }
end
