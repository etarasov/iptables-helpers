{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
module Iptables.Print where

import           Codec.Binary.UTF8.String (encodeChar)
import           Data.Monoid              ((<>))
import qualified Data.Set                 as Set
import           Data.Word
import           Iptables.Types
import           Numeric                  (showHex)
import           Safe                     (headMay)
import           Text.Pretty

prettyIptables :: Iptables -> String
prettyIptables = runPrinterStyle (style {mode = LeftMode}) . pretty

instance Pretty Iptables where
    pretty (Iptables f n m r) =
          prettyTable "filter" f
      </> prettyTable "nat" n
      </> prettyTable "mangle" m
      </> prettyTable "raw" r

prettyTable :: Printer -> [Chain] -> Printer
prettyTable _ [] = empty
prettyTable tableName chains =
    vcat [ "*" <> tableName
         , vcat (map prettyChainCaption chains)
         , vcat (map prettyChain chains)
         , "COMMIT"
         ]

prettyChainCaption :: Chain -> Printer
prettyChainCaption (Chain name policy counters _) =
    ":" <-> string name <+> pretty policy <+> pretty counters

prettyChain :: Chain -> Printer
prettyChain (Chain name _ _ rules) = vcat $ map (prettyRule name) rules

instance Pretty Policy where
    pretty ACCEPT     = "ACCEPT"
    pretty DROP       = "DROP"
    pretty PUNDEFINED = "-"

instance Pretty Counters where
    pretty (Counters a b) = brackets $ integer a <> ":" <> integer b

prettyRule :: String -> Rule -> Printer
prettyRule chainName (Rule counters ruleOpts target) =
    pretty counters <+> "-A" <+> string chainName <+> hsep (map pretty ruleOpts) <+> pretty target

instance Pretty RuleTarget where
    pretty rt = "-j" <+> prettyRuleTarget rt

prettyRuleTarget :: RuleTarget -> Printer
prettyRuleTarget TAccept         = "ACCEPT"
prettyRuleTarget TDrop           = "DROP"
prettyRuleTarget (TReject rw)    = "REJECT" <+> "--reject-with" <+> pretty rw
prettyRuleTarget TReturn         = "RETURN"
prettyRuleTarget (TUChain chain) = string chain
prettyRuleTarget (TSNat natAddr rand persist) =
    "SNAT" <+> "--to-source" <+> pretty natAddr <+> randS <+> persistS
  where randS    = option' rand "--random"
        persistS = option' persist "--persistent"
prettyRuleTarget (TDNat natAddr rand persist) =
    "DNAT" <+> "--to-destination" <+> pretty natAddr <+> randS <+> persistS
  where randS    = option' rand "--random"
        persistS = option' persist "--persistent"
prettyRuleTarget (TMasquerade natPort rand) =
    "MASQUERADE" <+> natPortS <+> randS
  where randS    = option' rand "--random"
        natPortS = case natPort of
                      NatPortDefault -> empty
                      _              -> "--to-ports" <+> pretty natPort
prettyRuleTarget (TRedirect natPort rand) =
    "REDIRECT" <+> natPortS <+> randS
  where randS    = option' rand "--random"
        natPortS = case natPort of
                      NatPortDefault -> empty
                      _              -> "--to-ports" <+> pretty natPort
prettyRuleTarget (TUnknown tName opts) = string tName <+> hsep (map string opts)

option' :: Bool -> Printer -> Printer
option' True doc = doc
option' False _  = empty

instance Pretty RejectType where
    pretty RTNetUnreachable   = "icmp-net-unreachable"
    pretty RTHostUnreachable  = "icmp-host-unreachable"
    pretty RTPortUnreachable  = "icmp-port-unreachable"
    pretty RTProtoUnreachable = "icmp-proto-unreachable"
    pretty RTNetProhibited    = "icmp-net-prohibited"
    pretty RTHostProhibited   = "icmp-host-prohibited"
    pretty RTAdminProhibited  = "icmp-admin-prohibited"
    pretty RTTcpReset         = "tcp-reset"

instance Pretty NatAddress where
    pretty (NAIp ip1 ip2) = prettyNatIp ip1 ip2
    pretty (NAIpPort ip1 ip2 port1 port2) =
        prettyNatIp ip1 ip2 <> ":" <> prettyNatIp port1 port2

instance Pretty NatPort where
    pretty NatPortDefault        = empty
    pretty (NatPort port1 port2) = prettyNatIp port1 port2

prettyNatIp :: (Eq a, Pretty a) => a -> a -> Printer
prettyNatIp ip1 ip2 | ip1 == ip2 = pretty ip1
                    | otherwise  = pretty ip1 <> "-" <> pretty ip2

instance Pretty RuleOption where
    pretty (OProtocol b p)         = prettyInv b <+> "-p" <+> string p
    pretty (OSource b addr)        = prettyInv b <+> "-s" <+> pretty addr
    pretty (ODest b addr)          = prettyInv b <+> "-d" <+> pretty addr
    pretty (OInInt b int)          = prettyInv b <+> "-i" <+> pretty int
    pretty (OOutInt b int)         = prettyInv b <+> "-o" <+> pretty int
    pretty (OSourcePort b p)       = prettyInv b <+> "--sport" <+> pretty p
    pretty (ODestPort b p)         = prettyInv b <+> "--dport" <+> pretty p
    pretty (OModule m)             = "-m" <+> pretty m
    pretty (OMacSource b m)        = prettyInv b <+> "--mac-source" <+> pretty m
    pretty (OState s)              = "--state" <+> pretty (Set.toList s)
    pretty (OPhysDevIsBridged b)   = prettyInv b <+> "--physdev-is-bridged"
    pretty (OComment c)            = "--comment" <+> prettyComment c
    pretty (OUnknown oName b opts) = prettyInv b <+> string oName <+> hsep (map string opts)

instance Pretty Addr where
    pretty (AddrIP ip)        = pretty ip
    pretty (AddrMask ip mask) = pretty ip <> "/" <> pretty mask
    pretty (AddrPref ip pref) = pretty ip <> "/" <> int pref

instance Pretty IP where
    pretty (IP a b c d) = sepBy "." $ map word8 [a, b, c, d]

word8 :: Word8 -> Printer
word8 = int . fromIntegral

instance Pretty Interface where
    pretty (Interface i) = string i

instance Pretty Port where
    pretty (Port ps)         = sepBy "," $ map int ps
    pretty (PortRange ps pe) = int ps <> ":" <> int pe

prettyInv :: Bool -> Printer
prettyInv True  = empty
prettyInv False = "!"

instance Pretty Limit where
    pretty (Limit l) = string l

instance Pretty CState where
    pretty CStInvalid     = "INVALID"
    pretty CStEstablished = "ESTABLISHED"
    pretty CStNew         = "NEW"
    pretty CStRelated     = "RELATED"
    pretty CStUntracked   = "UNTRACKED"

    prettyList = sepBy "," . map pretty

instance Pretty Module where
    pretty ModTcp       = "tcp"
    pretty ModUdp       = "udp"
    pretty ModLimit     = "limit"
    pretty ModMac       = "mac"
    pretty ModMark      = "mark"
    pretty ModMultiport = "multiport"
    pretty ModOwner     = "owner"
    pretty ModState     = "state"
    pretty ModTos       = "tos"
    pretty ModTtl       = "ttl"
    pretty ModPhysDev   = "physdev"
    pretty ModComment   = "comment"
    pretty (ModOther s) = string s

instance Pretty MacAddr where
    pretty (MacAddr a b c d e f) = sepBy ":" $ map prettyHex2 [a, b, c, d, e, f]

prettyHex2 :: Word8 -> Printer
prettyHex2 a | a < 16    = string $ '0' : showHex a ""
             | otherwise = string $ showHex a ""

prettyComment :: String -> Printer
prettyComment = string . printComment

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
