require 'webrick'

require_relative 'hmac'

KEY = Array.new(64) { rand(256) }.pack('c*').freeze
DELAY = (ARGV.first&.to_i || 50) / 1000.0

def insecure_compare(a, b)
  a.each_char.zip(b.each_char) { |x, y|
    return false if x != y
    Kernel.sleep(DELAY)
  }
  true
end

CACHE = {}

server = WEBrick::HTTPServer.new(Port: 8080)
server.mount_proc '/' do |req, res|
  begin
    file = req.query.fetch('file')
    CACHE[file] ||= hmac_sha1(KEY, req.query.fetch('file')).freeze
    seen = req.query.fetch('signature')

    if insecure_compare(CACHE[file], seen)
      res.body = 'yes'
      res.status = 200
    else
      res.body = 'no'
      res.status = 500
    end
  rescue => e
    res.body = e.message
    res.status = 500
  end
end

trap('INT') { server.shutdown }
puts "Expected for foo: #{hmac_sha1(KEY, 'foo')}"
server.start
