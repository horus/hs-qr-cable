{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-incomplete-patterns #-}

module Types where

import Codec.CBOR.Term
import Control.Monad (replicateM)
import Data.Attoparsec.ByteString.Char8 qualified as A
import Data.Binary as Binary (Binary (..), encode)
import Data.Binary.Get (getWord16le, getWord8)
import Data.Binary.Put (putWord16le, putWord8)
import Data.ByteString qualified as S
import Data.ByteString.Builder (byteStringHex, toLazyByteString)
import Data.ByteString.Lazy qualified as L (toStrict)
import Data.ByteString.Lazy.Char8 qualified as C8 (unpack)
import Data.Maybe (mapMaybe)
import Data.Word (Word16, Word8)

newtype Bytes = Bytes S.ByteString

instance Show Bytes where
  show (Bytes bs) = hexdump bs
    where
      hexdump = C8.unpack . toLazyByteString . byteStringHex

{--
// CableRequestType enumerates the types of connections that caBLE cares about.
// Unlike `FidoRequestType`, caBLE cares about the difference between making
// a discoverable and non-discoverable credential because this is flagged in
// the QR code.
--}
data CableRequestType = MakeCredential | DiscoverableMakeCredential | GetAssertion
  deriving (Show)

-- https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.h;drc=0e9a0b6e9bb6ec59521977eec805f5d0bca833e0;bpv=1;bpt=0;l=108

data Handshake = Handshake
  { peerIdentity :: Bytes,
    secret :: Bytes,
    {--
      // num_known_domains is the number of registered tunnel server domains known
      // to the device showing the QR code. Authenticators can use this to fallback
      // to a hashed domain if their registered domain isn't going to work with this
      // client.
    --}
    numKnownDomains :: Int,
    timestamp :: Int,
    {--
        // supports_linking is true if the device showing the QR code supports storing
        // and later using linking information. If this is false or absent, an
        // authenticator may wish to avoid bothering the user about linking.
    --}
    supportsLinking :: Bool,
    {--
      // request_type contains the hinted type of the request. This can
      // be used to guide UI ahead of receiving the actual request. This defaults to
      // `kGetAssertion` if not present or if the value in the QR code is unknown.
    --}
    requestType :: CableRequestType
  }
  deriving (Show)

-- https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.h;drc=cb95e30fa939a18bc0845b57b0946a102b86cf9d;l=82

data Eid = Eid
  { tunnelServerDomain :: Word16,
    -- // kRoutingIdSize is the number of bytes of routing information in the BLE advert.
    --    constexpr size_t kRoutingIdSize = 3;
    routingId :: [Word8],
    -- // kNonceSize is the number of bytes of nonce in the BLE advert.
    --    constexpr size_t kNonceSize = 10;
    nonce :: [Word8]
  }
  deriving (Show)

instance Binary Eid where
  get = do
    0 <- getWord8
    nonce <- replicateM 10 getWord8
    routingId <- replicateM 3 getWord8
    tunnelServerDomain <- getWord16le
    return $ Eid {..}
  put (Eid tunnelServerDomain routingId nonce) =
    putWord8 0 >> mapM_ putWord8 (nonce ++ routingId) >> putWord16le tunnelServerDomain

fromHeader :: S.ByteString -> Maybe Eid
fromHeader bs
  | S.length bs == 6 =
      let w8s = mapMaybe parseHex [S.take 2 bs, S.take 2 (S.drop 2 bs), S.takeEnd 2 bs]
       in return $ Eid 0 w8s (replicate 10 0) -- default 0
  | otherwise = Nothing
  where
    parseHex = either (const Nothing) Just . A.parseOnly A.hexadecimal

-- TODO: check lengths
eidToBytes :: Eid -> Bytes
eidToBytes = Bytes . L.toStrict . Binary.encode

fromTMap :: Term -> Either String Handshake
fromTMap (TMap m) = Handshake <$> p <*> s <*> d <*> t <*> l <*> r
  where
    p = look 0 $ \case TBytes bs -> pure $ Bytes bs
    s = look 1 $ \case TBytes bs -> pure $ Bytes bs
    d = look 2 $ \case TInt n -> pure n
    t = look 3 $ \case TInt n -> pure n
    l = look 4 $ \case TBool b -> pure b
    r = look 5 $ \case
      TString "mc" -> pure MakeCredential
      _ -> pure GetAssertion

    look :: Int -> (Term -> Either String a) -> Either String a
    look i f =
      let msg = Left $ "no value found at key " ++ show i
       in maybe msg f $ lookup (TInt i) m
-- not handled
fromTMap x =
  let typeOf = drop 1 . head . words . show -- magic
   in Left $ "expecting Map, but got " ++ typeOf x
