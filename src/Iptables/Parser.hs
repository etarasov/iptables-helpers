
module Iptables.Parser where

import Iptables.Types
import Control.Applicative ((<$>))
import Control.Monad.Error
import Data.Bits
import Data.Set (fromList)
import Data.Word
import Safe
import Text.ParserCombinators.Parsec

removeComments :: String -> String
removeComments input = unlines $ map removeComment $ lines input
    where
    removeComment :: String -> String
    removeComment ('#' : _) = ""
    removeComment a = a

parseIptables :: String -> Either ParseError Iptables
parseIptables = runParser iptables [] "input" . removeComments
    where
    iptables :: GenParser Char [Chain] Iptables
    iptables = do
        spaces
        tables <- many table
        let filterL = filter (isTable "filter") tables
        let filter' = headDef [] $ map snd filterL
        let natL = filter (isTable "nat") tables
        let nat = headDef [] $ map snd natL
        let mangleL = filter (isTable "mangle") tables
        let mangle = headDef [] $ map snd mangleL
        let rawL = filter (isTable "raw") tables
        let raw = headDef [] $ map snd rawL
        return $ Iptables filter' nat mangle raw

        where
        isTable :: String -> (String, a) -> Bool
        isTable n1 (n2, _) | n1 == n2 = True
                           | otherwise = False

    table :: GenParser Char [Chain] (String, [Chain])
    table = do
        many comment
        spaces
        char '*'
        tableName <- many1 letter
        when (tableName /= "filter" && tableName /= "nat" && tableName /= "mangle" && tableName /= "raw") $
             unexpected $ "table " ++ tableName ++ " is invalid"
        spaces
        chains_ <- chains
        spaces
        string "COMMIT"
        spaces
        return (tableName, chains_)

    comment :: GenParser Char [Chain] ()
    comment = char '#' >> manyTill anyChar (try (oneOf "\n\r")) >> spaces >> return ()

    chains :: GenParser Char [Chain] [Chain]
    chains = do
        -- chainDescrp and rule parsers put their output into state
        many chainDescr >> many rule
        res <- getState
        setState []
        return res

    chainDescr :: GenParser Char [Chain] ()
    chainDescr = do
        char ':'
        chainName <- chainNameParser
        spaces
        chainPolicyRaw <- many1 (letter <|> char '-')
        chainPolicy <- case chainPolicyRaw of
            "ACCEPT" -> return ACCEPT
            "DROP" -> return DROP
            "-" -> return PUNDEFINED
            a -> unexpected $ "unknown policy " ++ a
        spaces
        char '['
        packets <- fmap read $ many1 digit
        char ':'
        bytes <- fmap read $ many1 digit
        char ']'
        spaces
        st <- getState
        -- TODO: parse counters properly
        setState $ Chain chainName chainPolicy (Counters packets bytes) [] : st

    rule :: GenParser Char [Chain] ()
    rule = do
        counters <- option (Counters 0 0) $ do
            char '['
            packets <- fmap read $ many1 digit
            char ':'
            bytes <- fmap read $ many1 digit
            char ']'
            char ' '
            return $ Counters packets bytes
        string "-A"
        spaces
        chainName <- chainNameParser
        spaces
        matches <- many ruleOption
        string "-j"
        spaces
        target <- ruleTarget
        {- Skip unknown parameters
         - TODO: process all kinds of parameters
         -}
        many (noneOf "\n")
        spaces
        st <- getState
        let rule_ = Rule counters matches target
        let newState = addRuleToChain st chainName rule_
        setState newState

        -- Add rule into its chain
        where
            addRuleToChain :: [Chain] -> String -> Rule -> [Chain]
            addRuleToChain [] _ _ = []
            addRuleToChain (Chain n p c rs : xs) chName rule_ =
                if n == chName then
                    Chain n p c (rs ++ [rule_]) : xs
                               else
                    Chain n p c rs : addRuleToChain xs chName rule_

    ruleOption :: GenParser Char [Chain] RuleOption
    ruleOption =
        choice [ oProtocol, oSource, oDest, oInput, oOutput, oModule, oSrcPort, oDstPort, oState
               , oPhysDevIsBridged, oComment, oUnknown]
        where
        oProtocol = try $ do
            bool_ <- option True (char '!' >> char ' ' >> return False)
            try (string "-p") <|> string "--protocol"
            char ' '
            protocol <- many1 (letter <|> char '-')
            char ' '
            return $ OProtocol bool_ protocol

        oSource = try $ do
            bool_ <- option True (char '!' >> char ' ' >> return False)
            try (string "-s") <|> try (string "--src") <|> string "--source"
            char ' '
            address <- ipAddressParser
            char ' '
            return $ OSource bool_ address

        oDest = try $ do
            bool_ <- option True (char '!' >> char ' ' >> return False)
            try (string "-d") <|> try (string "--dst") <|> string "--destination"
            char ' '
            address <- ipAddressParser
            char ' '
            return $ ODest bool_ address

        oInput = try $ do
            bool_ <- option True (char '!' >> char ' ' >> return False)
            try (string "-i") <|> string "--in-interface"
            char ' '
            interf <- interfaceParser
            char ' '
            return $ OInInt bool_ $ Interface interf

        oOutput = try $ do
            bool_ <- option True (char '!' >> char ' ' >> return False)
            try (string "-o") <|> string "--out-interface"
            char ' '
            interf <- interfaceParser
            char ' '
            return $ OOutInt bool_ $ Interface interf

        oModule = do
            try (try (string "-m") <|> string "--match")
            char ' '
            mod_ <- many1 alphaNum
            char ' '
            case mod_ of
                "tcp" -> return $ OModule ModTcp
                "udp" -> return $ OModule ModUdp
                "state" -> return $ OModule ModState
                "physdev" -> return $ OModule ModPhysDev
                "comment" -> return $ OModule ModComment
                a -> return $ OModule $ ModOther a

        oSrcPort = try $ do
            bool_ <- option True (char '!' >> char ' ' >> return False)
            try (string "--sport") <|> string "--source-port"
            char ' '
            port <- ipPortParser
            char ' '
            return $ OSourcePort bool_ port

        oDstPort = try $ do
            bool_ <- option True (char '!' >> char ' ' >> return False)
            try (string "--dport") <|> string "--destination-port"
            char ' '
            port <- ipPortParser
            char ' '
            return $ ODestPort bool_ port

        oState = try $ do
            -- bool_ <- option True (char '!' >> char ' ' >> return False)
            string "--state"
            char ' '
            statesS <- sepBy (many1 alphaNum) $ char ','
            let parseState "INVALID" = return CStInvalid
                parseState "ESTABLISHED" = return CStEstablished
                parseState "RELATED" = return CStRelated
                parseState "NEW" = return CStNew
                parseState "UNTRACKED" = return CStUntracked
                parseState a = fail $ "There is no state " ++ a
            states <- mapM parseState statesS
            char ' '
            return $ OState $ fromList states

        oPhysDevIsBridged = try $ do
            bool_ <- option True (char '!' >> char ' ' >> return False)
            string "--physdev-is-bridged"
            char ' '
            return $ OPhysDevIsBridged bool_

        oComment = do
            try (string "--comment")
            many1 $ char ' '
            comment <- commentParser
            many $ char ' '
            return $ OComment comment

        oUnknown = try $ do
            bool_ <- option True (char '!' >> char ' ' >> return False)
            oN <- char '-'
            ame <- many1 (alphaNum <|> char '-')
            when (oN:ame == "-j") $
                fail "Option list is over"
            -- Option parameters - all words before next option or eol
            oParams <- fmap words $ manyTill anyChar ( try (lookAhead $ string " -")
                                                     <|> try (lookAhead $ string "\n")
                                                     <|> try (lookAhead $ string " !")
                                                     )
            char ' '
            return $ OUnknown (oN:ame) bool_ oParams

    ruleTarget :: GenParser Char [Chain] RuleTarget
    ruleTarget =
        choice [tAccept, tDrop, tMasquerade, tRedirect, tReject, tSNat, tDNat, tReturn, tUChain, tUnknown]
        where
        tAccept = do
            try $ string "ACCEPT"
            return TAccept

        tDrop = do
            try $ string "DROP"
            return TDrop

        tMasquerade = do
            try $ string "MASQUERADE"
            ports <- option NatPortDefault (try (string " --to-ports ") >> natPortParser)
            rand <- option False (try (char ' ' >> string "--random") >> return True)
            return $ TMasquerade ports rand

        tRedirect = do
            try $ string "REDIRECT"
            ports <- option NatPortDefault (try (string " --to-ports ") >> natPortParser)
            rand <- option False (try (char ' ' >> string "--random") >> return True)
            return $ TRedirect ports rand

        tReject = do
            try $ string "REJECT"
            rejectWith <- option RTPortUnreachable (try (string " --reject-with ") >> rejectTypeParser)
            return $ TReject rejectWith

        tSNat = try $ do
            string "SNAT"
            char ' '
            string "--to-source"
            char ' '
            addr <- natAddrParser
            rand <- option False (try (char ' ' >> string "--random") >> return True)
            persist <- option False (try (char ' ' >> string "--persistent") >> return True)
            return $ TSNat addr rand persist

        tDNat = try $ do
            string "DNAT"
            char ' '
            string "--to-destination"
            char ' '
            addr <- natAddrParser
            rand <- option False (try (char ' ' >> string "--random") >> return True)
            persist <- option False (try (char ' ' >> string "--persistent") >> return True)
            return $ TDNat addr rand persist

        tReturn = do
            try $ string "RETURN"
            return TReturn

        tUChain = try $ do
            chainName <- chainNameParser
            chains_ <- getState
            when (not $ chainName `elem` map cName chains_) $
                fail $ chainName ++ " is not name of real chain"
            return $ TUChain chainName

        tUnknown = do
            targetName <- chainNameParser
            opts <- option [] (char ' ' >> fmap words (many $ noneOf "\n"))
            return $ TUnknown targetName opts

-- TODO: move checks to ipAddrTyple function
ipMask :: GenParser Char st Addr
ipMask = do
    ip <- ipAddr
    char '/'
    mask <- ipAddr
    return $ AddrMask ip mask

ipPref :: GenParser Char st Addr
ipPref = do
    ip <- ipAddr
    char '/'
    prefS <- many1 (digit <?> "")
    let pref = read prefS
    when (pref > 32 || pref < 0) $
        fail "ip prefix >=0 && <= 32"
    return $ AddrPref ip pref

ipAddr :: GenParser Char st Word32
ipAddr = do
    as <- many1 (digit <?> "")
    let a = read as
    when (a > 255) $ fail "ip addr octet >= 0 && < 256"
    char '.'
    bs <- many1 (digit <?> "")
    let b = read bs
    when (b > 255) $ fail "ip addr octet >= 0 && < 256"
    char '.'
    cs <- many1 (digit <?> "")
    let c = read cs
    when (c > 255) $ fail "ip addr octet >= 0 && < 256"
    char '.'
    ds <- many1 (digit <?> "")
    let d = read ds
    when (d > 255) $ fail "ip addr octet >= 0 && < 256"
    return $ shiftL a 24 + shiftL b 16 + shiftL c 8 + d

ipAddressParser :: GenParser Char st Addr
ipAddressParser = try (ipMask <?> "ip address with mask")
                <|> try (ipPref <?> "ip address with prefix")
                <|> ((AddrIP <$> ipAddr) <?> "ip address")

checkPort :: Int -> GenParser Char st ()
checkPort a =
    when ( a < 0 || a > 65535) $
                    fail "port >= 0 && <= 65535"

checkPortRange :: Int -> Int -> GenParser Char st ()
checkPortRange p1 p2 =
    when ( p2 < p1 ) $
        fail "invalid port range"
{- 22:80
 - :80
 - 80:
 -}
ipPortRange :: GenParser Char st Port
ipPortRange = do
    start <- option 0 (fmap read $ many1 digit)
    checkPort start
    char ':'
    end <- option 65535 (fmap read $ many1 digit)
    checkPort end
    checkPortRange start end
    return $ PortRange start end

ipPort :: GenParser Char st Port
ipPort = do
    portsS <- sepBy1 (many1 digit) $ char ','
    let ports = map read portsS
    mapM_ checkPort ports
    return $ Port ports

ipPortParser :: GenParser Char st Port
ipPortParser = try ipPortRange <|> ipPort

interfaceParser :: GenParser Char st String
interfaceParser = do
    -- Можно написать -i + или -o +, но такое правило сохранится вообще без параметра -i или -o
    name <- many1 alphaNum
    plus <- option [] (fmap (: []) $ char '+')
    return $ name ++ plus

natAddrParser :: GenParser Char st NatAddress
natAddrParser = (natIpPort <?> "nat ip(s) and port(s)") <|>
                natIp

natIp :: GenParser Char st NatAddress
natIp = do
    ip1 <- ipAddr
    ip2 <- option ip1 (char '-' >> ipAddr)
    return $ NAIp ip1 ip2

natIpPort :: GenParser Char st NatAddress
natIpPort = do
    (ip1, ip2) <- try ( do
        ip1 <- ipAddr
        ip2 <- option ip1 (char '-' >> ipAddr)
        char ':'
        return (ip1, ip2)
        )
    port1S <- many1 digit
    let port1 = read port1S
    checkPort port1
    port2S <- option port1S (char '-' >> many1 digit)
    let port2 = read port2S
    checkPort port2
    checkPortRange port1 port2
    return $ NAIpPort ip1 ip2 port1 port2

natPortParser :: GenParser Char st NatPort
natPortParser = do
    port1S <- many1 digit
    let port1 = read port1S
    checkPort port1
    port2S <- option port1S (char '-' >> many1 digit)
    let port2 = read port2S
    checkPort port2
    checkPortRange port1 port2
    return $ NatPort port1 port2

rejectTypeParser :: GenParser Char st RejectType
rejectTypeParser = do
    rw <- many1 (letter <|> char '-')
    case rw of
        "icmp-net-unreachable" -> return RTNetUnreachable
        "icmp-host-unreachable" -> return RTHostUnreachable
        "icmp-port-unreachable" -> return RTPortUnreachable
        "icmp-proto-unreachable" -> return RTProtoUnreachable
        "icmp-net-prohibited" -> return RTNetProhibited
        "icmp-host-prohibited" -> return RTHostProhibited
        "icmp-admin-prohibited" -> return RTAdminProhibited
        "tcp-reset" -> return RTTcpReset
        a -> fail $ "Unknown reject type: " ++ a

chainNameParser :: GenParser Char st String
chainNameParser = many1 (alphaNum <|> char '-' <|> char '_')

commentParser :: GenParser Char st String
commentParser =
    try ( do
        char '\''
        manyTill anyChar (try $ char '\'')
        )
    <|>
    try ( do
        char '"'
        manyTill anyChar (try $ char '"')
        )
    <|> many1 (noneOf " \n\r\t")
