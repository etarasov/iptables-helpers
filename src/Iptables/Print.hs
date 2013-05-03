
module Iptables.Print where

import Codec.Binary.UTF8.String
import Data.Bits
import Data.List
import Data.Set (toList)
import Data.Word
import Iptables.Types
import Safe

printIptables :: Iptables -> String
printIptables (Iptables f n m r) =
    (if null f then "" else printTable "filter" f)
    ++ (if null n then "" else printTable "nat" n)
    ++ (if null m then "" else printTable "mangle" m)
    ++ (if null r then "" else printTable "raw" r)
    where
        printTable :: String -> [Chain] -> String
        printTable tableName chains =
            "*" ++ tableName ++ "\n"
            ++ unlines (map printChainCaption chains)
            ++ concat (map printChain chains)
            ++ "COMMIT\n"

        printChainCaption :: Chain -> String
        printChainCaption (Chain name policy counters _) =
            ":" ++ name ++ " "
            ++ printPolicy policy ++ " "
            ++ printCounters counters

        printPolicy :: Policy -> String
        printPolicy p = case p of
            ACCEPT -> "ACCEPT"
            DROP -> "DROP"
            PUNDEFINED -> "-"

printChain :: Chain -> String
printChain (Chain name _ _ rules) =
    unlines (map (printRule name) rules)

printCounters :: Counters -> String
printCounters (Counters a b) = "[" ++ show a ++ ":" ++ show b ++ "]"

printRuleForRun :: Rule -> String
printRuleForRun (Rule _ ruleOpts target) =
    unwords (map printOption ruleOpts) ++ " "
    ++ printTarget target

printRule :: String -> Rule -> String
printRule chainName (Rule counters ruleOpts target) =
    printCounters counters ++ " "
    ++ "-A " ++ chainName ++ " "
    ++ unwords (map printOption ruleOpts) ++ " "
    ++ printTarget target

printOption :: RuleOption -> String
printOption opt = case opt of
    (OProtocol b p) -> unwords $ printInv b ++ ["-p"] ++ [p]
    (OSource b addr) -> unwords $ printInv b ++ ["-s"] ++ [printAddress addr]
    (ODest b addr) -> unwords $ printInv b ++ ["-d"] ++ [printAddress addr]
    (OInInt b int) -> unwords $ printInv b ++ ["-i"] ++ [printInterface int]
    (OOutInt b int) -> unwords $ printInv b ++ ["-o"] ++ [printInterface int]
    (OFragment b) -> undefined b
    (OSourcePort b p) -> unwords $ printInv b ++ ["--sport"] ++ [printPort p]
    (ODestPort b p) -> unwords $ printInv b ++ ["--dport"] ++ [printPort p]
    (OTcpFlags b fs) -> undefined b fs
    (OSyn b) -> undefined b
    (OTcpOption b o) -> undefined b o
    (OIcmpType b t) -> undefined b t
    (OModule m) -> unwords $ "-m" : [printModule m]
    (OLimit b l) -> undefined b l
    (OLimitBurst b) -> undefined b
    (OMacSource b m) -> undefined b m
    (OMark a b) -> undefined a b
    (OPort b p) -> undefined b p
    (OUidOwner b u) -> undefined b u
    (OGidOwner b g) -> undefined b g
    (OSidOwner b s) -> undefined b s
    (OState s) -> unwords $ "--state" : [printStates $ toList s]
    (OTos t) -> undefined t
    (OTtl t) -> undefined t
    (OPhysDevIn b int) -> undefined b int
    (OPhysDevOut b int) -> undefined b int
    (OPhysDevIsIn b) -> undefined b
    (OPhysDevIsOut b) -> undefined b
    (OPhysDevIsBridged b) -> unwords $ printInv b ++ ["--physdev-is-bridged"]
    (OComment c) -> "--comment" ++ " " ++ printComment c
    (OUnknown oName b opts) -> unwords $ printInv b ++ [oName] ++ opts

printInv :: Bool -> [String]
printInv True = []
printInv False = ["!"]

printTarget :: RuleTarget -> String
printTarget rt = (++) "-j " $ case rt of
                            TAccept -> "ACCEPT"
                            TDrop -> "DROP"
                            TReject rw -> "REJECT" ++ " --reject-with " ++ printRejectWith rw
                            TReturn -> "RETURN"
                            TUChain chain -> chain
                            TSNat natAddr rand persist ->
                                let randS = if rand then " --random"
                                                    else ""
                                    persistS = if persist then " --persistent"
                                                           else ""
                                in
                                    "SNAT " ++ "--to-source " ++ printNatAddr natAddr ++ randS ++ persistS
                            TDNat natAddr rand persist ->
                                let randS = if rand then " --random"
                                                    else ""
                                    persistS = if persist then " --persistent"
                                                          else ""
                                in
                                    "DNAT " ++ "--to-destination " ++ printNatAddr natAddr ++ randS ++ persistS
                            TMasquerade natPort rand ->
                                let randS = if rand then " --random"
                                                    else ""
                                    natPortS = case natPort of
                                        NatPortDefault -> ""
                                        _ -> " --to-ports " ++ printNatPort natPort
                                in
                                    "MASQUERADE" ++ natPortS ++ randS
                            TRedirect natPort rand ->
                                let randS = if rand then " --random"
                                                    else ""
                                    natPortS = case natPort of
                                        NatPortDefault -> ""
                                        _ -> " --to-ports " ++ printNatPort natPort
                                in
                                    "REDIRECT" ++ natPortS ++ randS
                            TUnknown tName opts ->
                                tName ++ " " ++ unwords opts

printAddress :: Addr -> String
printAddress (AddrIP ip) = printIp ip
printAddress (AddrMask ip mask) = printIp ip ++ "/" ++ printIp mask
printAddress (AddrPref ip pref) = printIp ip ++ "/" ++ show pref

printIp :: Word32 -> String
printIp ip =
    let oct1 = show $ shiftR ip 24
        oct2 = show $ shiftR (shiftL ip 8) 24
        oct3 = show $ shiftR (shiftL ip 16) 24
        oct4 = show $ shiftR (shiftL ip 24) 24
    in oct1 ++ "." ++ oct2 ++ "." ++ oct3 ++ "." ++ oct4

printInterface :: Interface -> String
printInterface (Interface str) = str

printPort :: Port -> String
printPort (Port ps) = intercalate "," $ map show ps
printPort (PortRange ps pe) = show ps ++ ":" ++ show pe

printStates :: [CState] -> String
printStates ss = intercalate "," $ map printState ss
    where
    printState st = case st of
            CStInvalid -> "INVALID"
            CStEstablished -> "ESTABLISHED"
            CStNew -> "NEW"
            CStRelated -> "RELATED"
            CStUntracked -> "UNTRACKED"

printModule :: Module -> String
printModule m = case m of
        ModTcp -> "tcp"
        ModUdp -> "udp"
        ModLimit -> "limit"
        ModMac -> "mac"
        ModMark -> "mark"
        ModMultiport -> "multiport"
        ModOwner -> "owner"
        ModState -> "state"
        ModTos -> "tos"
        ModTtl -> "ttl"
        ModPhysDev -> "physdev"
        ModComment -> "comment"
        ModOther s -> s

printNatAddr :: NatAddress -> String
printNatAddr (NAIp ip1 ip2) = printNatIp ip1 ip2
printNatAddr (NAIpPort ip1 ip2 port1 port2) = printNatIpPort ip1 ip2 port1 port2

printNatIp :: Word32 -> Word32 -> String
printNatIp ip1 ip2 =
    if ip1 == ip2 then printIp ip1
                  else printIp ip1 ++ "-" ++ printIp ip2

printNatIpPort :: Word32 -> Word32 -> Int -> Int -> String
printNatIpPort ip1 ip2 port1 port2 =
    let ipString = if ip1 == ip2 then printIp ip1
                                else printIp ip1 ++ "-" ++ printIp ip2
        portString = if port1 == port2 then show port1
                                       else show port1 ++ "-" ++ show port2
    in
        ipString ++ ":" ++ portString

printNatPort :: NatPort -> String
printNatPort NatPortDefault = ""
printNatPort (NatPort port1 port2) =
    if port1 == port2
        then show port1
        else show port1 ++ "-" ++ show port2

printRejectWith :: RejectType -> String
printRejectWith rw = case rw of
    RTNetUnreachable -> "icmp-net-unreachable"
    RTHostUnreachable -> "icmp-host-unreachable"
    RTPortUnreachable -> "icmp-port-unreachable"
    RTProtoUnreachable -> "icmp-proto-unreachable"
    RTNetProhibited -> "icmp-net-prohibited"
    RTHostProhibited -> "icmp-host-prohibited"
    RTAdminProhibited -> "icmp-admin-prohibited"
    RTTcpReset -> "tcp-reset"

-- | Iptables doesn't work correctly with russian chars.
-- It's working only if a comment is enclosed with single quotes and it doesn't include spaces.
-- Let's assume that this happens with all multibyte chars.
printComment :: String -> String
printComment com =
    let onlyOneByteChars :: String -> Bool
        onlyOneByteChars [] = True
        onlyOneByteChars (x:xs) = if length (encodeChar x) > 1 then True
                                                    else onlyOneByteChars xs
    in
    if onlyOneByteChars com
        then "\"" ++ com ++ "\""
        else 
            let com' = if headMay com == Just '\'' then com
                                                   else "'" ++ com ++ "'"
                com'' = if null (filter (== ' ') com') then com'
                                                      else (map (\a -> if a == ' ' then '_' else a) com')
            in com''
