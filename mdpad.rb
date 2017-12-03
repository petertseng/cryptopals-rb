def mdpad(message, endianness)
  raise "Unknown endianness #{endianness}" unless %i(big little).include?(endianness)

  padded = message.bytes
  bit_length = padded.size * 8

  # Append 1 and some number of zeroes.
  # It is safe to add byte 0x80 instead of bit 1,
  # since input strings are an integer number of bytes,
  # and thus bit lengths 441..447 will never occur.
  padded << 0x80
  len_mod_64 = padded.size % 64
  zeroes_needed = len_mod_64 <= 56 ? 56 - len_mod_64 : 64 - (len_mod_64 - 56)
  padded.concat([0] * zeroes_needed)
  raise "Padded to wrong length #{padded.length}" if padded.length % 64 != 56

  # Append length
  length_bytes = bit_length.digits(256)
  length_bytes.concat([0] * (8 - length_bytes.size))
  length_bytes.reverse! if endianness == :big
  padded.concat(length_bytes)

  padded.pack('c*')
end
