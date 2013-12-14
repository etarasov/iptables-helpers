import Test.DocTest

main ::  IO ()
main = doctest ["-isrc:test", "test/Iptables/Types/Arbitrary.hs", "src/Iptables/Print.hs"]
