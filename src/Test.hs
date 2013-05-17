{-# LANGUAGE DeriveDataTypeable#-}

module Main where

import Control.Monad
import Data.Generics
import Data.List
import Iptables
import Iptables.Parser
import Iptables.Print
import Iptables.Types
import Iptables.Types.Arbitrary
import System.Console.GetOpt
import System.Environment
import System.Exit
import Test.QuickCheck hiding (Result())
import Test.QuickCheck.Property

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
    --        putStrLn $ "Trying to open '" ++ file ++ "' ..."
            a <- readFile file
            let b = parseIptables a
            case b of
                Left er -> do
                    putStrLn "Decoding failed:"
                    putStrLn $ show er
                Right res -> do
     --               putStrLn "Iptables config has been parsed:"
                    putStrLn $ printIptables $ sortIptables res
            exitSuccess
        Nothing -> return ()

    when ( Gen `elem` opts) $ do
        testData <- sample' (arbitrary :: Gen Iptables)
        putStr $ printIptables $ sortIptables $ testData !! 6
        exitSuccess

    when (Test `elem` opts) $ do
        quickCheck tryToParsePrint
        exitSuccess

tryToParsePrint :: Iptables -> Result
tryToParsePrint a = case parseIptables $ printIptables $ sortIptables a of
    Left err -> MkResult (Just False) True
                                      (show err ++ "\n" ++ printIptables (sortIptables a))
                                      False False [] []
    Right res ->
        let a' = sortIptables a
            res' = sortIptables res
        in
        if a' == res' then MkResult (Just True) True "" False False [] []
                      else MkResult (Just False) True
                                    ( printIptables a' ++ "\n" ++ printIptables res'
                                    ++ iptablesDiff a' res'
                                    )
                                    False False [] []

iptablesDiff :: Iptables -> Iptables -> String
iptablesDiff ip1 ip2 =
    if map cName (tFilter ip1) /= map cName (tFilter ip2)
        then
            "1: \n" ++ show (map cName $ tFilter ip1)
            ++ "\n" ++ show (map cName $ tFilter ip2)
        else ""
    ++ if map cName (tNat ip1) /= map cName (tNat ip2)
        then
            "1: \n" ++ show (map cName $ tNat ip1)
            ++ "\n" ++ show (map cName $ tNat ip2)
        else ""
    ++ if map cName (tMangle ip1) /= map cName (tMangle ip2)
        then
            "1: \n" ++ show (map cName $ tMangle ip1)
            ++ "\n" ++ show (map cName $ tMangle ip2)
        else ""
    ++ if map cName (tRaw ip1) /= map cName (tRaw ip2)
        then
            "1: \n" ++ show (map cName $ tRaw ip1)
            ++ "\n" ++ show (map cName $ tRaw ip2)
        else ""
    ++ tableDiff (tFilter ip1) (tFilter ip2)
    ++ tableDiff (tNat ip1) (tNat ip2)
    ++ tableDiff (tMangle ip1) (tMangle ip2)
    ++ tableDiff (tRaw ip1) (tRaw ip2)

tableDiff :: [Chain] -> [Chain] -> String
tableDiff [] (c:cx) = "Table 2 has more chains: " ++ show (map cName (c:cx))
tableDiff (c:cx) [] = "Table 1 has more chains: " ++ show (map cName (c:cx))
tableDiff [] [] = ""
tableDiff (c1:cx1) (c2:cx2) = chainDiff c1 c2 ++ tableDiff cx1 cx2

chainDiff :: Chain -> Chain -> String
chainDiff c1 c2 =
    if cName c1 /= cName c2
        then
            "Chains have different names: " ++ cName c1 ++ "/" ++ cName c2 ++ "\n"
        else
            if cPolicy c1 /= cPolicy c2
                then "Chains nave different policy:\n" ++ (show $ cPolicy c1) ++ "/" ++ (show $ cPolicy c2) ++ "\n"
                else ""
            ++ rulesDiff (cRules c1) (cRules c2)

rulesDiff :: [Rule] -> [Rule] -> String
rulesDiff rs1 rs2 =
    concat $ zipWith (\ r1 r2 -> 
        let equal = r1 == r2
        in
        if equal
            then ""
            else
                show equal ++ "\n"
                ++ show r1 ++ "\n"
                ++ show r2
            ) rs1 rs2
