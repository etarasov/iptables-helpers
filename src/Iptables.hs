module Iptables where

import Data.List hiding (insert)
import Data.Maybe
import Data.Set hiding (map, filter, null)
import Iptables.Types
import Control.Monad
import Control.Monad.State

{- | Список необходимых модулей для опций
 - --dport не требует -m tcp
 - -p tcp требует -m tcp
 - проверка на зависимость --dport от -p проверяется в другом месте
 -}
optionDepends :: RuleOption -> [Module]
optionDepends (OProtocol True "tcp") = [ModTcp]
optionDepends (OProtocol True "udp") = [ModUdp]
optionDepends (OState _) = [ModState]
optionDepends (OComment _) = [ModComment]
optionDepends _ = []

{- Пользовательские цепочки могут быть залупленные.
 - Проверка на залупляемость производится только при добавлении ссылки во встраиваемые цепочки
 -
 - Определение типа цепочки:
 - Если в состоянии есть уже это имя, то произошло залупливание, возвращаем NatInvalidChain
 - Если встроенное имя, то тип, соответствующий этому имени
 - Если есть противоречащие правила, то NatInvalidChain
 - Если есть хотя бы одно правило, то тип, относящийся к этому правилу
 - Добавляем своё имя в состояние (множество имён)
 - Ищем ссылку на правило (возвращаемое значение Maybe тип цепочки)
 - Если рез-тат Just a, то a
 - Если Nothing, то NatUnknownChain
 -}

-- Поиск цепочки впереди для предотвращения направленных циклов
findChainForward :: String -> [Chain] -> String -> Bool
findChainForward chainToFind chains currentChain =
    if chainToFind == currentChain
        then True
        else
            let chain = fromJust $ getChainByName currentChain chains
                linkingChains = scanChainForLinks chain
                resL = map (findChainForward chainToFind chains) linkingChains
            in
                or resL

type ChainNames = Set String

-- Один полный проход вперёд c поиском циклов
guessFilterChainType :: String -> [Chain] -> FilterChainType
guessFilterChainType chainName chains =
    let (_, (_, chainType)) = runState (traverseForward chains chainName) (empty, FilterValidChain)
    in chainType

    where
    traverseForward :: [Chain] -> String -> State (ChainNames, FilterChainType) ()
    traverseForward chains' chainName' = do
        (names, chainType) <- get
        let test1 = if chainName' `member` names
                then Just FilterInvalidChain
                else Nothing
        case test1 of
            Just _ -> put (empty, FilterInvalidChain)
            Nothing -> do
                put (insert chainName' names, chainType)
                let linkingChains = scanChainForLinks $ fromJust $ getChainByName chainName' chains'
                mapM_ (traverseForward chains') linkingChains

-- Один полный проход назад, один вперёд
guessNatChainType :: String -> [Chain] -> NatChainType
guessNatChainType chainName chains =
    let (_, (_, types)) = runState ( do
                                        traverseForward chains chainName
                                        (_, types') <- get
                                        put (empty, types')
                                        traverseBackward chains chainName
                                  ) (empty, empty)
    in if NatInvalidChain `member` types
           then NatInvalidChain
       else if NatDNatChain `member` types && NatSNatChain `member` types
           then NatInvalidChain
       else if NatDNatChain `member` types
           then NatDNatChain
       else if NatSNatChain `member` types
           then NatSNatChain
       else NatUnknownChain

    where
    traverseForward :: [Chain] -> String -> State (ChainNames, Set NatChainType) ()
    traverseForward chains' chainName' = do
        processChain chains' chainName'
        -- dangerous place - fromJust
        let linkingChains = scanChainForLinks $ fromJust $ getChainByName chainName' chains'
        mapM_ (traverseForward chains') linkingChains

    traverseBackward :: [Chain] -> String -> State (ChainNames, Set NatChainType) ()
    traverseBackward chains' chainName' = do
        processChain chains' chainName'
        let linkingChains = scanTableForLink chainName' chains'
        mapM_ (traverseBackward chains') linkingChains

    processChain :: [Chain] -> String -> State (ChainNames, Set NatChainType) ()
    processChain chains' chainName' = do
        (names, types) <- get
        let test1 = if chainName' `member` names
                then Just NatInvalidChain
                else Nothing
        let test2 = case chainName' of
                "PREROUTING" -> Just NatDNatChain
                "POSTROUTING" -> Just NatSNatChain
                "OUTPUT" -> Just NatDNatChain
                _ -> Nothing
        let chain = fromJust $ getChainByName chainName' chains'
        let snatTarget = hasChainSNatTarget $ cRules chain
        let dnatTarget = hasChainDNatTarget $ cRules chain
        let test3 = if snatTarget && dnatTarget
                then Just NatInvalidChain
                else Nothing
        let test4 = if snatTarget
                then Just NatSNatChain
                else Nothing
        let test5 = if dnatTarget
                then Just NatDNatChain
                else Nothing
        {- actually perform tests
         - msum returns first success or Nothing
         -}
        let resMay = msum [test1, test2, test3, test4, test5]
        case resMay of
            Just chainType -> put (names, insert chainType types)
            Nothing -> return ()

        {- Chain type can't be determined by itself
         - try to analyse its callers if they exists
         -}
        (names', types') <- get
        put (insert chainName' names', types')

-- Возвращает список цепочек, которые ссылаются на заданную именем пользовательскую цепочку
scanTableForLink :: String -> [Chain] -> [String]
scanTableForLink chainName chains =
    let resMayL = map (scanChainForLink chainName) chains
    in catMaybes resMayL

    where
    scanChainForLink :: String           -- ^ name of user defined chain
                     -> Chain            -- ^ chain to scan for a link
                     -> Maybe String     -- ^ name of chain containing link
    scanChainForLink name (Chain n _ _ rs) =
        if scanChainForLink' name rs then Just n
                                     else Nothing
        where

        scanChainForLink' :: String -> [Rule] -> Bool
        scanChainForLink' _ [] = False
        scanChainForLink' chainName' (r : rs') =
            if TUChain chainName' == rTarget r
                then True
                else scanChainForLink' chainName' rs'

scanChainForLinks :: Chain -> [String]
scanChainForLinks (Chain _ _ _ rs) =
    scanRulesForLinks rs
    where
    scanRulesForLinks :: [Rule] -> [String]
    scanRulesForLinks [] = []
    scanRulesForLinks (Rule _ _ (TUChain chainName) : rs') = chainName : scanRulesForLinks rs'
    scanRulesForLinks (_ : rs') = scanRulesForLinks rs'

getChainByName :: String -> [Chain] -> Maybe Chain
getChainByName _ [] = Nothing
getChainByName chainName (Chain n p cs rs : xs) | chainName == n = Just $ Chain n p cs rs
                                                | otherwise = getChainByName chainName xs

hasChainSNatTarget :: [Rule] -> Bool
hasChainSNatTarget [] = False
hasChainSNatTarget (Rule _ _ (TMasquerade _ _) : _) = True
hasChainSNatTarget (Rule _ _ (TSNat _ _ _) : _) = True
hasChainSNatTarget (_ : xs) = hasChainSNatTarget xs

hasChainDNatTarget :: [Rule] -> Bool
hasChainDNatTarget [] = False
hasChainDNatTarget (Rule _ _ (TDNat _ _ _) : _) = True
hasChainDNatTarget (Rule _ _ (TRedirect _ _) : _) = True
hasChainDNatTarget (_ : xs) = hasChainDNatTarget xs

isFilterBuiltinChain :: String -> Bool
isFilterBuiltinChain chain =
    case chain of
        "INPUT" -> True
        "FORWARD" -> True
        "OUTPUT" -> True
        _ -> False

isNatBuiltinChain :: String -> Bool
isNatBuiltinChain chain =
    case chain of
        "PREROUTING" -> True
        "POSTROUTING" -> True
        "OUTPUT" -> True
        _ -> False

isMangleBuiltinChain :: String -> Bool
isMangleBuiltinChain chain =
    case chain of
        "INPUT" -> True
        "PREROUTING" -> True
        "FORWARD" -> True
        "POSTROUTING" -> True
        "OUTPUT" -> True
        _ -> False

isFilterType :: FilterChainType     -- ^ Type to test
             -> [Chain]             -- ^ Filter table
             -> String              -- ^ The chain name
             -> Bool
isFilterType chainType table chain =
    let chainType' = guessFilterChainType chain table
    in chainType == chainType'

isNatType :: NatChainType    -- ^ Type to test
          -> [Chain]         -- ^ Nat table
          -> String          -- ^ The chain name
          -> Bool
isNatType chainType table chain =
    let chainType' = guessNatChainType chain table
    in chainType == chainType'

sortFilterTable :: [Chain] -> [Chain]
sortFilterTable table =
    let userChains = filter (not . isFilterBuiltinChain . cName) table
    in
        filter (("INPUT" ==) . cName) table
        ++ filter (("FORWARD" ==) . cName) table
        ++ filter (("OUTPUT" ==) . cName) table
        ++ sortBy (\ c1 c2 -> compare (cName c1) (cName c2)) userChains

sortNatTable :: [Chain] -> [Chain]
sortNatTable table =
    let userChains = filter (not . isNatBuiltinChain . cName) table
    in
        filter (("PREROUTING" ==) . cName) table
        ++ filter (("POSTROUTING" ==) . cName) table
        ++ filter (("OUTPUT" ==) . cName) table
        ++ sortBy (\ c1 c2 -> compare (cName c1) (cName c2)) userChains

sortMangleTable :: [Chain] -> [Chain]
sortMangleTable table =
    let userChains = filter (not . isMangleBuiltinChain . cName) table
    in
        filter (("INPUT" ==) . cName) table
        ++ filter (("PREROUTING" ==) . cName) table
        ++ filter (("FORWARD" ==) . cName) table
        ++ filter (("POSTROUTING" ==) . cName) table
        ++ filter (("OUTPUT" ==) . cName) table
        ++ sortBy (\ c1 c2 -> compare (cName c1) (cName c2)) userChains
