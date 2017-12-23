require 'zlib'

require_relative 'aes_cbc'
require_relative 'assert'
require_relative 'xor'

SESSION = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='.freeze

def format_request(p)
  [
    'POST / HTTP/1.1',
    'Host: hapless.com',
    "Cookie: sessionid=#{SESSION}",
    "Content-Length: #{p.size}",
    # I believe in actual HTTP there is a newline here too?
    p,
  ].join("\n")
end

def oracle(encrypt)
  ->(p) {
    encrypt[Zlib::Deflate.deflate(format_request(p))].size
  }
end

one_time_pad_xor = ->(p) {
  otp = Array.new(p.size) { rand(256) }
  xor(p.bytes, otp).pack('c*')
}

cbc = ->(p) {
  pad_len = 16 - p.size % 16
  iv = Array.new(16) { rand(256) }
  key = Array.new(16) { rand(256) }.pack('c*')
  aes_cbc_encrypt(p.bytes + [pad_len] * pad_len, key: key, iv: iv)
}

base64 = [(?a..?z), (?A..?Z), (?0..?9), [?+, ?/, ?=, "\n"]].map { |r| r.to_a.join }.join.freeze

# Assume attacker doesn't know session length?
TRY_UNTIL = 100

{otp_xor: one_time_pad_xor, cbc: cbc}.each { |name, encrypt|
  puts "Encryption #{name}"

  original_oracle = oracle(encrypt)

  # In CBC, to deal with the padding,
  # we need to make the difference between right/wrong larger.
  # This is achieved by replicating the string we're testing.
  # I don't yet know why 32, 8, and 4 work.
  # Experimentally determined.
  oracle = name == :cbc ? ->(p) { original_oracle[(p + 0.chr) * (p.size < 32 ? 8 : 4)] } : original_oracle

  good_prefix = 'sessionid='
  possible_prefixes = [''.freeze].freeze

  loop {
    min = oracle[good_prefix + 0.chr * (possible_prefixes[0].size + 1)]
    bests = []

    possible_prefixes.each { |pp|
      base64.each_char { |c|
        len = oracle[good_prefix + pp + c]
        if len < min
          min = len
          bests = [pp + c]
        elsif len == min
          bests << pp + c
        end
      }
    }

    if bests.size == 1
      if bests[0] == "\n"
        assert_eq("sessionid=#{SESSION}", good_prefix)
        break
      end
      good_prefix << bests[0]
      possible_prefixes = [''.freeze].freeze
    elsif bests.size == 0
      raise 'No bests?'
    elsif bests[0][0..-2] == bests[-1][0..-2]
      good_prefix << bests[0][0..-2]
      if good_prefix.end_with?("\n")
        assert_eq("sessionid=#{SESSION}", good_prefix.chomp)
        break
      end
      possible_prefixes = bests.map { |s| s[-1].freeze }.freeze
    else
      possible_prefixes = bests.freeze
      raise 'This is usually a bad case; we have an explosion of possibilities'
    end

    puts "Now #{good_prefix} + #{possible_prefixes.size} possible prefixes of length #{possible_prefixes[0].size}" if name == :cbc
    raise 'NOT FOUND' if good_prefix.size + possible_prefixes[0].size > TRY_UNTIL
  }
}
