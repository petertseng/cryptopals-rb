def hex_to_bytes(s)
  s.chars.each_slice(2).map { |a| Integer(a.join, 16) }
end

def bytes_to_hex(l)
  l.map { |b| '%02x' % b }.join
end
