module Iptables.ParserSpec where

import           Test.Hspec
import           Test.QuickCheck

import           Iptables                 (sortIptables)
import           Iptables.Parser          (parseIptables)
-- import           Iptables.Print           (printIptables)
import           Iptables.Types           (Iptables, prettyIptables)
import           Iptables.Types.Arbitrary ()

spec :: Spec
spec = do
    describe "parseIptables" $ do
      it "should parse iptables" $ do
        property checkIptablesParser

checkIptablesParser :: Iptables -> Bool
checkIptablesParser ast =
    case parseIptables (prettyIptables ast) of
      Left _  -> False
      Right a -> sortIptables ast == sortIptables a
