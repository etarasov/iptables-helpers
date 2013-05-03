module Main where

import Iptables.Print
import Iptables.Types
import Iptables.Types.Arbitrary
import System.Console.GetOpt
import Test.QuickCheck

main :: IO ()
main = do
    testData <- sample' (arbitrary :: Gen Iptables)
    putStr $ printIptables $ testData !! 6
