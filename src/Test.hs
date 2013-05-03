{-# LANGUAGE DeriveDataTypeable#-}

module Main where

import Control.Monad
import Data.Generics
import Data.List
import Iptables.Parser
import Iptables.Print
import Iptables.Types
import Iptables.Types.Arbitrary
import System.Console.GetOpt
import System.Environment
import System.Exit
import Test.QuickCheck

-- GetOpt stuff --------------------------------------

data GOFlag = Version
            | Help
            | ParseFile FilePath
            | Test
            | Gen
            deriving (Eq, Ord, Show, Typeable, Data)

options = [ Option ['h'] ["help"] (NoArg Help) "Print this help message"
          , Option [] ["parse"] (ReqArg (\a -> ParseFile a) "<file>") "Parse file. Example: test --parse ./iptables-save.dat"
          , Option [] ["test"] (NoArg Test) "Run tests"
          , Option [] ["generate"] (NoArg Gen) "Generate example iptables config in iptables-save -c format"
          ]

------------------------------------------------------

main :: IO ()
main = do
    args <- getArgs
    let (opts, params, errs) = getOpt RequireOrder options args

    when (not $ null errs) $ do
        putStr $ concat $ nub errs
        exitFailure

    when (Help `elem` opts) $ do
        putStrLn "Iptables-helpers testing utility"
        putStr $ usageInfo "Usage:" options
        exitSuccess

    let getParseFile :: GOFlag -> Maybe FilePath
        getParseFile (ParseFile a) = Just a
        getParseFile _ = Nothing

    case everything mplus (mkQ Nothing getParseFile) opts of
        Just file -> do
            putStrLn $ "Trying to open '" ++ file ++ "' ..."
            a <- readFile file
            let b = parseIptables a
            case b of
                Left er -> do
                    putStrLn "Decoding failed:"
                    putStrLn $ show er
                Right res -> do
                    putStrLn "Iptables config has been parsed:"
                    putStrLn $ printIptables res
            exitSuccess
        Nothing -> return ()

    when ( Gen `elem` opts) $ do
        testData <- sample' (arbitrary :: Gen Iptables)
        putStr $ printIptables $ testData !! 6
        exitSuccess

    when (Test `elem` opts) $ do
        quickCheck tryToParsePrint
        exitSuccess

tryToParsePrint :: Iptables -> Bool
tryToParsePrint a = case parseIptables $ printIptables a of
    Left err -> False
    Right res -> a == res
