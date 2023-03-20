{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-incomplete-patterns #-}

module Types where

import Codec.CBOR.Term
import Data.ByteString.Lazy (ByteString)
import Util (hexdump')

{--
// CableRequestType enumerates the types of connections that caBLE cares about.
// Unlike `FidoRequestType`, caBLE cares about the difference between making
// a discoverable and non-discoverable credential because this is flagged in
// the QR code.
--}
data CableRequestType = MakeCredential | DiscoverableMakeCredential | GetAssertion
  deriving (Show)

-- https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.h;drc=0e9a0b6e9bb6ec59521977eec805f5d0bca833e0;bpv=1;bpt=0;l=108

data HandshakeComponents = HandshakeComponents
  { peerIdentity :: ByteString,
    secret :: ByteString,
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

fromTMap :: Term -> Either String HandshakeComponents
fromTMap (TMap m) = HandshakeComponents <$> p <*> s <*> d <*> t <*> l <*> r
  where
    p = look 0 $ \case TBytes bs -> pure $ hexdump' bs
    s = look 1 $ \case TBytes bs -> pure $ hexdump' bs
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