module Iptables.Types where

import           Data.Set  (Set)
import           Data.Word

data Iptables = Iptables { tFilter :: [Chain]
                         , tNat    :: [Chain]
                         , tMangle :: [Chain]
                         , tRaw    :: [Chain]
                         }
                         deriving (Show, Eq)

data Chain = Chain { cName     :: String
                   , cPolicy   :: Policy
                   , cCounters :: Counters
                   , cRules    :: [Rule]
                   }
                   deriving (Show)

-- | Discard counters
instance Eq Chain where
    (==) (Chain name1 policy1 _ rules1) (Chain name2 policy2 _ rules2) =
        (name1 == name2) && (policy1 == policy2) && (rules1 == rules2)

data Policy = ACCEPT
            | DROP
            | PUNDEFINED
            deriving (Show, Eq)

data Counters = Counters { cPackets :: Integer
                         , cBytes   :: Integer
                         }
                         deriving (Show, Eq)

data Rule = Rule { rCounters :: Counters
                 , rOptions  :: [RuleOption]
                 , rTarget   :: RuleTarget
                 }
                 deriving (Show)

-- | Discard counters
instance Eq Rule where
    (==) (Rule _ opts1 tar1) (Rule _ opts2 tar2) = (opts1 == opts2) && (tar1 == tar2)

data RuleTarget = TAccept
                | TDrop
                | TReject RejectType
                | TReturn
                | TSNat NatAddress Bool Bool -- --to-source --random --persistent
                | TDNat NatAddress Bool Bool
                | TMasquerade NatPort Bool   -- --to-ports --random
                | TRedirect NatPort Bool     -- --to-ports --random
                | TUChain String
                | TUnknown String [String]
                deriving (Show, Eq)

data RejectType = RTNetUnreachable
                | RTHostUnreachable
                | RTPortUnreachable  -- Default if not specified
                | RTProtoUnreachable
                | RTNetProhibited
                | RTHostProhibited
                | RTAdminProhibited
                | RTTcpReset
                deriving (Show, Eq)

data NatAddress = NAIp IP IP
                | NAIpPort IP IP Int Int
                deriving (Show, Eq)

data NatPort = NatPort Int Int
             | NatPortDefault
             deriving (Show, Eq)

data RuleOption = OProtocol Bool Protocol
                | OSource Bool Addr
                | ODest Bool Addr
                | OInInt Bool Interface
                | OOutInt Bool Interface
                | OState (Set CState)
                | OFragment Bool
                | OSourcePort Bool Port
                | ODestPort Bool Port
                | OTcpFlags Bool TcpFlags
                | OSyn Bool
                | OTcpOption Bool Int
                | OIcmpType Bool Int
                | OModule Module
                | OLimit Bool Limit
                | OLimitBurst Int
                | OMacSource Bool MacAddr
                | OMark Int Int
                | OPort Bool Port
                | OUidOwner Bool Int
                | OGidOwner Bool Int
                | OSidOwner Bool Int
                | OTos Int
                | OTtl Int
                | OPhysDevIn Bool Interface
                | OPhysDevOut Bool Interface
                | OPhysDevIsIn Bool
                | OPhysDevIsOut Bool
                | OPhysDevIsBridged Bool
                | OComment String
                | OUnknown String Bool [String]   -- option can have more than one parameters
                deriving (Show, Eq)

{- We can work only with strings. In iptables, a protocol can be specified by integer number,
 - but we don't use this feature.
 -}
type Protocol = String

data Addr = AddrIP IP
          | AddrMask IP IP
          | AddrPref IP Int
          deriving (Show, Eq)

data IP = IP Word8 Word8 Word8 Word8
        deriving (Show, Eq)

newtype Interface = Interface String
                  deriving (Show, Eq)

data Port = Port [Int]
          | PortRange Int Int
          deriving (Show, Eq)

-- Парсить осторожно - в тексте это 2 слова, разделённых пробелами
data TcpFlags = TcpFlags [Flag] [Flag]
          deriving (Show, Eq)

data Flag = FSyn
          | FAck
          | FFin
          | FRst
          | FUrg
          | FPsh
          | FAll
          | FNone
          deriving (Show, Eq)

newtype Limit = Limit String
          deriving (Show, Eq)

data CState = CStInvalid
            | CStEstablished
            | CStNew
            | CStRelated
            | CStUntracked
            deriving (Show, Eq, Ord)

data Module = ModTcp
            | ModUdp
            | ModLimit
            | ModMac
            | ModMark
            | ModMultiport
            | ModOwner
            | ModState
            | ModTos
            | ModTtl
            | ModPhysDev
            | ModComment
            | ModOther String
            deriving (Show, Eq)

data FilterChainType = FilterInvalidChain
                     | FilterValidChain
                     deriving (Show, Eq)

data NatChainType = NatUnknownChain
                  | NatInvalidChain
                  | NatDNatChain
                  | NatSNatChain
                  deriving (Show, Eq, Ord)

data MacAddr = MacAddr Word8 Word8 Word8 Word8 Word8 Word8
             deriving (Show, Eq, Ord)
