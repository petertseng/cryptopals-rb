require_relative 'assert'

class BadPad < StandardError; end

def unpkcs7(bytes)
  pad = bytes.last(bytes.last)
  raise BadPad.new(pad) unless pad.all? { |x| x == pad[0] } && pad.size == pad[0]
  bytes[0...-pad.size]
end

assert_eq('ICE ICE BABY'.bytes, unpkcs7('ICE ICE BABY'.bytes + [4] * 4))
assert_eq(:threw, begin unpkcs7('ICE ICE BABY'.bytes + [5] * 4) rescue BadPad; :threw end)
assert_eq(:threw, begin unpkcs7('ICE ICE BABY'.bytes + [1, 2, 3, 4]) rescue BadPad; :threw end)
