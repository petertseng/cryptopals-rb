require_relative 'aes_cbc'
require_relative 'assert'

KEY = Array.new(16) { rand(256) }.freeze
FIXED_IV = ([0] * 16).freeze

def cbc_mac(p, key:, iv: nil)
  iv ||= Array.new(16) { rand(256) }
  c = aes_cbc_encrypt(p, key: key, iv: iv)
  [iv, c[-16..-1]]
end

def api_server(accounts, req, attacker_iv: false, single: false, list: false)
  raise "Bad config, need only one of single or list not #{single} #{list}" if single == list

  mac = req[-16..-1]
  iv = attacker_iv ? req[-32..-17] : FIXED_IV
  msg = req[0..(attacker_iv ? -33 : -17)]
  _, expected_mac = cbc_mac(msg, key: KEY.pack('c*'), iv: iv)
  if mac != expected_mac
    puts " Got: #{mac}"
    puts "Want: #{expected_mac}"
    return 401
  end

  puts "Got: #{msg[0...-msg[-1]].pack('c*').inspect}"
  begin
    params = msg[0...-msg[-1]].pack('c*').split(?&).map { |p|
      l, r = p.split(?=)
      r = if l == 'tx_list'
        r.split(?;).map { |ta|
          # Vulnerability: Doesn't check that each element is an integer
          #ta.split(?:).map { |x| Integer(x) }
          ta.split(?:).map(&:to_i)
        }
      else
        Integer(r)
      end
      [l.to_sym, r]
    }.to_h
  rescue => e
    puts e
    return 400
  end

  return 400 unless from = params[:from]
  return 404 unless accounts.has_key?(from)

  transactions = begin
    single ? [[params.fetch(:to), params.fetch(:amount)]] : params.fetch(:tx_list)
  rescue => e
    puts e
    return 400
  end

  transactions.each { |to, amt|
    return 400 if amt < 0
    return 404 unless accounts.has_key?(to)
    # Maybe error if account would become negative?
  }

  transactions.each { |to, amt|
    accounts[from] -= amt
    accounts[to] += amt
  }

  accounts.freeze
end

def single_client(my_account)
  my_account = Integer(my_account)
  ->(to_account, amount) {
    to_account = Integer(to_account)
    amount = Integer(amount)
    msg = "from=#{my_account}&to=#{to_account}&amount=#{amount}".bytes
    pad_len = 16 - msg.size % 16
    msg.concat([pad_len] * pad_len)
    [msg] + cbc_mac(msg, key: KEY.pack('c*'))
  }
end

def list_client(my_account)
  my_account = Integer(my_account)
  ->(transactions) {
    # Vulnerability: Should check that we only have integer arguments.
    #transactions = transactions.map { |ta| ta.map { |t_or_a| Integer(t_or_a) }.join(?:) }.join(?;)
    raise 'nope' if transactions.any? { |t, a| t.nil? || a.nil? }
    transactions = transactions.map { |ta| ta.join(?:) }.join(?;)
    msg = "from=#{my_account}&tx_list=#{transactions}".bytes
    pad_len = 16 - msg.size % 16
    msg.concat([pad_len] * pad_len)
    [msg] + cbc_mac(msg, key: KEY.pack('c*'), iv: FIXED_IV)
  }
end

ATTACKERS_ACCOUNT = 1
VICTIMS_ACCOUNT = 2
AMOUNT_TO_STEAL = 1_000_000
attackers_client = single_client(ATTACKERS_ACCOUNT)
msg, iv, mac = attackers_client[ATTACKERS_ACCOUNT, AMOUNT_TO_STEAL]
# May be slightly harder if victim's account ID is longer!
bit_to_flip = msg.index(?=.ord) + 1
flip_by = ATTACKERS_ACCOUNT.to_s.ord ^ VICTIMS_ACCOUNT.to_s.ord

accounts = {ATTACKERS_ACCOUNT => 0}
assert_eq(accounts, api_server(accounts, msg + iv + mac, attacker_iv: true, single: true), '(with attacker IV) unaltered message accepted')

msg[bit_to_flip] ^= flip_by
iv = iv.dup
iv[bit_to_flip] ^= flip_by
iv.freeze

accounts = {ATTACKERS_ACCOUNT => 0, VICTIMS_ACCOUNT => AMOUNT_TO_STEAL}
assert_eq(
  {ATTACKERS_ACCOUNT => AMOUNT_TO_STEAL, VICTIMS_ACCOUNT => 0},
  api_server(accounts, msg + iv + mac, attacker_iv: true, single: true),
  '(with attacker IV) altered message accepted',
)

iv = nil

SOMEONE_ELSES_ACCOUNT = 3
victims_client = list_client(VICTIMS_ACCOUNT)
msg, _, mac = victims_client[[[SOMEONE_ELSES_ACCOUNT, 1]]]
accounts = {ATTACKERS_ACCOUNT => 0, VICTIMS_ACCOUNT => 1, SOMEONE_ELSES_ACCOUNT => 0}
assert_eq(
  {ATTACKERS_ACCOUNT => 0, VICTIMS_ACCOUNT => 0, SOMEONE_ELSES_ACCOUNT => 1},
  api_server(accounts, msg + mac, list: true),
  '(with fixed IV) unaltered message accepted',
)

# I would like to add another block of plaintext.
# However, how will I get a MAC for the new message?
# the input to the block cipher is previous_mac XOR block_to_add,
# but we don't know the key, so we can only ask the web client to make some MACs.
#
# We can observe the MAC of a one-block message.
# We can craft a two-block message whose second block differs from block_to_add
# by exactly how much the one_block_mac differs from previous_mac.
# We ask the client to generate the MAC of that message,
# and the input to the block cipher will be equal to previous_mac XOR block_to_add.
# Thus, we can acquire a MAC for the message we want.
#
# This is mostly right except that `from=1&tx_list=1` takes up one block,
# so we'll instead do this with the second/third blocks.

attackers_client = list_client(ATTACKERS_ACCOUNT)
msg2, _, mac2 = attackers_client[[[ATTACKERS_ACCOUNT, 0]]]
puts "Generated MAC for #{msg2.pack('c*').inspect}"

steal = ";#{ATTACKERS_ACCOUNT}:#{AMOUNT_TO_STEAL}".bytes
# TODO: Does it still work if steal is larger than a whole block?
raise "Haven't figured out how to do it with #{steal.size}" if steal.size >= 16
# We pad our steal string to a full block so that we know what to XOR with.
# Since the client will pad before sending to the server,
# it doesn't matter whether this is PCKS#7 padding.
# So we'll use semicolons.
pad_len = 16 - steal.size % 16
steal.concat([?;.ord] * pad_len)

msg3, _, mac3 = attackers_client[[[
  # This assumes a certain vulnerability in the client:
  # It accepts arbitrary strings as amounts (doesn't check that they're integers)
  # This is necessary because we need to ask it to generate a MAC for a specific string.
  # Neither the semicolon nor colon appear in this string (typically),
  # so we must put them all inside the amount.
  ATTACKERS_ACCOUNT,
  [
    ?0,
    msg2[-(msg2[-1])..-1].pack('c*'),
    steal.zip(mac, mac2).map { |c, m1, m2| c ^ m1 ^ m2 }.pack('c*'),
  ].join
]]]
puts "Generated MAC for #{msg3.pack('c*').inspect}"

accounts = {ATTACKERS_ACCOUNT => 0, VICTIMS_ACCOUNT => AMOUNT_TO_STEAL + 1, SOMEONE_ELSES_ACCOUNT => 0}
assert_eq(
  {ATTACKERS_ACCOUNT => AMOUNT_TO_STEAL, VICTIMS_ACCOUNT => 0, SOMEONE_ELSES_ACCOUNT => 1},
  # Remember, the client padded our message, so we need to pad here too.
  api_server(accounts, msg + steal + [16] * 16 + mac3, list: true),
  '(with fixed IV) altered message accepted',
)
