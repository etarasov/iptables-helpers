{-# OPTIONS_GHC -fno-warn-orphans #-}
module Iptables.Types.Arbitrary where

import           Control.Applicative
import           Data.Bits
import qualified Data.Set            as Set
import           Data.Word
import           Iptables.Types
import           Test.QuickCheck

instance Arbitrary Iptables where
    arbitrary = do
        userFilterChainsNum <- choose (0,4)
        let uniqueChains :: [Chain] -> Bool
            uniqueChains chains = length (map cName chains) == Set.size (Set.fromList (map cName chains))
        userFilterChains <- suchThat (vectorOf userFilterChainsNum userFilterChain) uniqueChains
        let userFilterChainNames = map cName userFilterChains

        inputChain' <- inputChain userFilterChainNames
        forwardChain' <- forwardChain userFilterChainNames
        outputFilterChain' <- outputFilterChain userFilterChainNames

        userNatChainsNum <- choose (0,4)
        userNatChains <- suchThat (vectorOf userNatChainsNum userNatChain) uniqueChains
        let userNatChainNames = map cName userNatChains

        preroutingChain' <- preroutingChain userNatChainNames
        postroutingChain' <- postroutingChain userNatChainNames
        outputNatChain' <- outputNatChain userNatChainNames

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

inputChain :: [String] -> Gen Chain
inputChain userChains = Chain <$> pure "INPUT"
                              <*> arbitrary
                              <*> arbitrary
                              <*> do
                                   rulesNum <- choose (0,20)
                                   vectorOf rulesNum $ filterRule userChains

forwardChain :: [String] -> Gen Chain
forwardChain userChains = Chain <$> pure "FORWARD"
                                 <*> arbitrary
                                 <*> arbitrary
                                 <*> do
                                    rulesNum <- choose (0,10)
                                    vectorOf rulesNum $ filterRule userChains

outputFilterChain :: [String] -> Gen Chain
outputFilterChain userChains = Chain <$> pure "OUTPUT"
                                      <*> arbitrary
                                      <*> arbitrary
                                      <*> do
                                        rulesNum <- choose (0,20)
                                        vectorOf rulesNum $ filterRule userChains

preroutingChain :: [String] -> Gen Chain
preroutingChain userChains = Chain <$> pure "PREROUTING"
                                    <*> arbitrary
                                    <*> arbitrary
                                    <*> do
                                        rulesNum <- choose (0,3)
                                        vectorOf rulesNum $ natRule userChains

postroutingChain :: [String] -> Gen Chain
postroutingChain userChains = Chain <$> pure "POSTROUTING"
                                     <*> arbitrary
                                     <*> arbitrary
                                     <*> do
                                        rulesNum <- choose (0,3)
                                        vectorOf rulesNum $ natRule userChains

outputNatChain :: [String] -> Gen Chain
outputNatChain userChains = Chain <$> pure "OUTPUT"
                                   <*> arbitrary
                                   <*> arbitrary
                                   <*> do
                                        rulesNum <- choose (0,1)
                                        vectorOf rulesNum $ natRule userChains

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
            vectorOf rulesNum $ filterRule [name]

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
            vectorOf rulesNum $ natRule [name]

filterRule :: [String] -> Gen Rule
filterRule userChains = do
    target <- oneof $ [ return TAccept
                      , return TDrop
                      , TReject <$> arbitrary
                      , return TReturn
                      ]
                      ++ if null userChains then []
                            else [ TUChain <$> elements userChains]
    Rule <$> arbitrary
         <*> do
            optNum <- choose (0,3)
            vectorOf optNum arbitrary
         <*> pure target

natRule :: [String] -> Gen Rule
natRule userChains = do
    target <- oneof $ [ return TAccept
                      , return TDrop
                      , return TReturn
                      , TSNat <$> arbitrary <*> arbitrary <*> arbitrary
                      , TDNat <$> arbitrary <*> arbitrary <*> arbitrary
                      , TMasquerade <$> arbitrary <*> arbitrary
                      , TRedirect <$> arbitrary <*> arbitrary
                      ]
                      ++ if null userChains then []
                          else [TUChain <$> elements userChains]
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

instance Arbitrary Rule where
    arbitrary = Rule <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary RuleTarget where
    arbitrary = oneof [ return TAccept
                      , return TDrop
                      , TReject <$> arbitrary
                      , return TReturn
                      , TSNat <$> arbitrary <*> arbitrary <*> arbitrary
                      , TDNat <$> arbitrary <*> arbitrary <*> arbitrary
                      , TMasquerade <$> arbitrary <*> arbitrary
                      , TRedirect <$> arbitrary <*> arbitrary
                      , TUChain <$> arbitrary
                      , TUnknown <$> arbitrary <*> arbitrary
                      ]

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

ipMask :: Gen IP
ipMask = do
    let a = maxBound :: Word32
    networkBits <- choose (1,32)
    return . toIP $ shiftL a networkBits
  where
    toIP :: Word32 -> IP
    toIP ip = IP oct1 oct2 oct3 oct4
      where
        oct1 = fromIntegral $ shiftR ip 24
        oct2 = fromIntegral $ shiftR (shiftL ip 8) 24
        oct3 = fromIntegral $ shiftR (shiftL ip 16) 24
        oct4 = fromIntegral $ shiftR (shiftL ip 24) 24

instance Arbitrary NatAddress where
    arbitrary =
        oneof [ NAIp <$> arbitrary <*> arbitrary
              , do
                    port1 <- choose (1,65535)
                    port2 <- choose (port1, 65535)
                    NAIpPort <$> arbitrary <*> arbitrary <*> pure port1 <*> pure port2
              ]

instance Arbitrary NatPort where
    arbitrary =
        oneof [ do
                port1 <- choose (1,65535)
                port2 <- oneof [ choose (port1, 65535)
                               , return port1
                               ]
                return $ NatPort port1 port2
              , return NatPortDefault
              ]

instance Arbitrary RuleOption where
    arbitrary =
        oneof [ OProtocol <$> arbitrary <*> elements ["tcp", "udp"]
              , OSource <$> arbitrary <*> arbitrary
              , ODest <$> arbitrary <*> arbitrary
              , OInInt <$> arbitrary <*> arbitrary
              , OOutInt <$> arbitrary <*> arbitrary
              , OState <$> (vectorOf 3 arbitrary >>= return . Set.fromList )
              , OSourcePort <$> arbitrary <*> arbitrary
              , ODestPort <$> arbitrary <*> arbitrary
              , OModule <$> arbitrary
              --, OPort <$> arbitrary <*> arbitrary
              --, OPhysDevIn <$> arbitrary <*> arbitrary
              --, OPhysDevOut <$> arbitrary <*> arbitrary
              , OComment <$> pure "test comment"
              , OMacSource <$> arbitrary <*> arbitrary
              , OUnknown <$> pure "--unknown" <*> arbitrary <*> pure ["opt"]
              ]

instance Arbitrary Addr where
    arbitrary =
        oneof [ AddrIP <$> arbitrary
              , AddrMask <$> arbitrary <*> ipMask
              , AddrPref <$> arbitrary <*> choose (1,32)
              ]

instance Arbitrary IP where
    arbitrary = IP <$> choose (0,255)
                   <*> choose (0,255)
                   <*> choose (0,255)
                   <*> choose (0,255)

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
                 , ModState
                 , ModPhysDev
                 , ModComment
                 , ModOther "unknown"
                 ]

instance Arbitrary MacAddr where
    arbitrary = MacAddr <$> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
