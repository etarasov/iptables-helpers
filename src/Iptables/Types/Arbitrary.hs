module Iptables.Types.Arbitrary where

import Control.Applicative
import Data.Bits
import Data.Set
import Data.Word
import Iptables.Types
import Test.QuickCheck

instance Arbitrary Iptables where
    arbitrary = do
        inputChain' <- inputChain
        forwardChain' <- forwardChain
        outputFilterChain' <- outputFilterChain

        userFilterChainsNum <- choose (0,4)
        userFilterChains <- vectorOf userFilterChainsNum userFilterChain

        preroutingChain' <- preroutingChain
        postroutingChain' <- postroutingChain
        outputNatChain' <- outputNatChain

        userNatChainsNum <- choose (0,4)
        userNatChains <- vectorOf userNatChainsNum userNatChain

        return $ Iptables ( [ inputChain'
                            , forwardChain'
                            , outputFilterChain'
                            ] ++ userFilterChains
                          )
                          ( [ preroutingChain'
                            , postroutingChain'
                            , outputNatChain'
                            ] ++ userNatChains
                          )
                          []
                          []

inputChain :: Gen Chain
inputChain = Chain <$> pure "INPUT"
                   <*> arbitrary
                   <*> arbitrary
                   <*> do
                        rulesNum <- choose (0,20)
                        vectorOf rulesNum filterRule

forwardChain :: Gen Chain
forwardChain = Chain <$> pure "FORWARD"
                     <*> arbitrary
                     <*> arbitrary
                     <*> do
                        rulesNum <- choose (0,10)
                        vectorOf rulesNum filterRule

outputFilterChain :: Gen Chain
outputFilterChain = Chain <$> pure "OUTPUT"
                          <*> arbitrary
                          <*> arbitrary
                          <*> do
                            rulesNum <- choose (0,20)
                            vectorOf rulesNum filterRule

preroutingChain :: Gen Chain
preroutingChain = Chain <$> pure "PREROUTING"
                        <*> arbitrary
                        <*> arbitrary
                        <*> do
                            rulesNum <- choose (0,3)
                            vectorOf rulesNum natRule

postroutingChain :: Gen Chain
postroutingChain = Chain <$> pure "POSTROUTING"
                         <*> arbitrary
                         <*> arbitrary
                         <*> do
                            rulesNum <- choose (0,3)
                            vectorOf rulesNum natRule

outputNatChain :: Gen Chain
outputNatChain = Chain <$> pure "OUTPUT"
                       <*> arbitrary
                       <*> arbitrary
                       <*> do
                            rulesNum <- choose (0,1)
                            vectorOf rulesNum natRule

userFilterChain :: Gen Chain
userFilterChain = do
    nameLen <- choose (1,10)
    name <- vectorOf nameLen $ elements $ ['a'..'z']
                                        ++ ['A'..'Z']
                                        ++ ['0'..'9']
    Chain <$> pure name
          <*> pure PUNDEFINED
          <*> arbitrary
          <*> do
            rulesNum <- choose (0,10)
            vectorOf rulesNum filterRule

userNatChain :: Gen Chain
userNatChain = do
    nameLen <- choose (1,10)
    name <- vectorOf nameLen $ elements $ ['a'..'z']
                                        ++ ['A'..'Z']
                                        ++ ['0'..'9']
    Chain <$> pure name
          <*> pure PUNDEFINED
          <*> arbitrary
          <*> do
            rulesNum <- choose (0,4)
            vectorOf rulesNum natRule

filterRule :: Gen Rule
filterRule = do
    target <- oneof [ return TAccept
                    , return TDrop
                    , TReject <$> arbitrary
                    , return TReturn
                    , TUChain <$> (listOf $ elements $ ['a'..'z'] ++ ['A'..'Z'] ++ ['0'..'9'])
                    ]
    Rule <$> arbitrary
         <*> do
            optNum <- choose (0,3)
            vectorOf optNum arbitrary
         <*> pure target
        
natRule :: Gen Rule
natRule = do
    target <- oneof [ return TAccept
                    , return TDrop
                    , return TReturn
                    , TSNat <$> arbitrary <*> arbitrary <*> arbitrary
                    , TDNat <$> arbitrary <*> arbitrary <*> arbitrary
                    , TMasquerade <$> arbitrary <*> arbitrary
                    , TRedirect <$> arbitrary <*> arbitrary
                    , TUChain <$> (listOf $ elements $ ['a'..'z'] ++ ['A'..'Z'] ++ ['0'..'9'])
                    ]
    Rule <$> arbitrary
         <*> do
            optNum <- choose (0,3)
            vectorOf optNum arbitrary
         <*> pure target

instance Arbitrary Policy where
    arbitrary = elements [ACCEPT, DROP]

instance Arbitrary Counters where
    arbitrary = Counters <$> choose (0,100000)
                         <*> choose (0,10000000)

instance Arbitrary RejectType where
    arbitrary = elements [ RTNetUnreachable
                         , RTHostUnreachable
                         , RTPortUnreachable
                         , RTProtoUnreachable
                         , RTNetProhibited
                         , RTHostProhibited
                         , RTAdminProhibited
                         , RTTcpReset
                         ]

ipAddress :: Gen Word32
ipAddress = do
    a <- choose (0,255)
    b <- choose (0,255)
    c <- choose (0,255)
    d <- choose (0,255)
    return $ shiftL a 24 + shiftL b 16 + shiftL c 8 + d

ipMask :: Gen Word32
ipMask = do
    let a = maxBound :: Word32
    networkBits <- choose (1,32)
    return $ shiftL a networkBits

instance Arbitrary NatAddress where
    arbitrary =
        oneof [ NAIp <$> ipAddress <*> ipAddress
              , NAIpPort <$> ipAddress <*> ipAddress <*> choose (1,65535) <*> choose (1,65535)
              ]

instance Arbitrary NatPort where
    arbitrary =
        oneof [ NatPort <$> arbitrary <*> arbitrary
              , return NatPortDefault
              ]

instance Arbitrary RuleOption where
    arbitrary =
        oneof [ OProtocol <$> arbitrary <*> elements ["tcp", "udp"]
              , OSource <$> arbitrary <*> arbitrary
              , ODest <$> arbitrary <*> arbitrary
              , OInInt <$> arbitrary <*> arbitrary
              , OOutInt <$> arbitrary <*> arbitrary
              , OState <$> (vectorOf 3 arbitrary >>= return . fromList )
              , OSourcePort <$> arbitrary <*> arbitrary
              , ODestPort <$> arbitrary <*> arbitrary
              , OModule <$> arbitrary
              --, OPort <$> arbitrary <*> arbitrary
              --, OPhysDevIn <$> arbitrary <*> arbitrary
              --, OPhysDevOut <$> arbitrary <*> arbitrary
              , OComment <$> pure "test comment"
              , OUnknown <$> pure "--unknown" <*> arbitrary <*> pure ["opt"]
              ]

instance Arbitrary Addr where
    arbitrary =
        oneof [ AddrIP <$> ipAddress
              , AddrMask <$> ipAddress <*> ipMask
              , AddrPref <$> ipAddress <*> choose (1,32)
              ]

instance Arbitrary Interface where
    arbitrary = Interface <$> elements ["eth0","eth1","eth2","br0","br1","wlan0","wlan1","ppp0","ppp1"]

instance Arbitrary CState where
    arbitrary = elements [CStInvalid, CStEstablished, CStNew, CStRelated, CStUntracked]

instance Arbitrary Port where
    arbitrary =
        oneof [ Port <$> listOf1 (choose (1,65535))
              , PortRange <$> choose (1,1000) <*> choose (1001, 65535)
              ]

instance Arbitrary Module where
    arbitrary =
        elements [ ModTcp
                 , ModUdp
                 , ModLimit
                 , ModState
                 , ModPhysDev
                 , ModComment
                 , ModOther "unknown"
                 ]
