require_relative 'aes_cbc'
require_relative 'assert'

def bad_hash(bytes)
  initial_state = Array.new(bytes) { rand(256) }.freeze
  pad_len = 16 - bytes
  pad = ([pad_len] * pad_len).freeze
  ->(m) {
    h = initial_state.dup
    m.each_slice(16) { |mi|
      h = aes_cbc_encrypt(mi, key: (h + pad).pack('c*'), iv: [0] * 16)[0, bytes]
    }
    h
  }
end

def collisions(n, hasher)
  n.times.with_object([]) { |_, collisions|
    collide = {}
    loop {
      block = Array.new(16) { rand(256) }
      hash = hasher[collisions.flat_map(&:first) + block]
      if collide.has_key?(hash)
        collisions << [collide[hash], block]
        break
      end
      collide[hash] = block
    }
  }
end

N1 = 2
bad_hash_cheap = bad_hash(N1)

TEST_N = 4
test = collisions(TEST_N, bad_hash_cheap)
assert_eq(TEST_N, test.size)
assert_eq([2] * TEST_N, test.map(&:size))
hash = bad_hash_cheap[test.flat_map(&:first)]
colliding_messages = test[0].product(*test[1..-1])
assert_eq(2 ** TEST_N, colliding_messages.size)
colliding_messages.each { |blocks|
  assert_eq(hash, bad_hash_cheap[blocks.flatten])
}

N2 = 4
bad_hash_less_cheap = bad_hash(N2)

0.step { |n|
  # Find colliding messages for cheap hash.
  t = Time.now
  # N2 is a byte size, we want a bit size. N2 * 8 / 2
  cheap_collisions = collisions(N2 * 4, bad_hash_cheap)
  puts "Try #{n}: Have collisions in #{Time.now - t}"

  t = Time.now
  collide = {}
  cheap_collisions[0].product(*cheap_collisions[1..-1]) { |blocks|
    msg = blocks.flatten
    hash = bad_hash_less_cheap[msg]
    if collide.has_key?(hash)
      puts "Try #{n}: Found collision in #{Time.now - t}: #{collide[hash]}, #{msg}"
      [bad_hash_cheap, bad_hash_less_cheap].each { |hasher|
        assert_eq(hasher[collide[hash]], hasher[msg])
      }
      Kernel.exit(0)
    end
    collide[hash] = msg
  }
  puts "Try #{n}: No collisions yet in #{Time.now - t}"
}
