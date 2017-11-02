def assert_eq(want, got, msg = nil)
  raise "No#{msg && " on #{msg}"}, got #{got}, want #{want}" if got != want
end
