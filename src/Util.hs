{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Util where

import Crypto.Hash (SHA256, hashlazy)
import Data.Bits (Bits (unsafeShiftR), shiftR, unsafeShiftL, (.&.), (.|.))
import Data.ByteArray qualified as ByteArray (unpack)
import Data.ByteString qualified as S
import Data.ByteString.Builder
import Data.ByteString.Lazy qualified as L
import Data.ByteString.Lazy.Char8 qualified as C8
import Data.Char (toUpper)
import Data.Int (Int64)
import Data.List (unfoldr)
import Data.Maybe (fromMaybe)
import Data.Word (Word64)
import Derive (hkdfSha256)
import Types (Bytes(..))

chunksOf :: Int64 -> L.ByteString -> [L.ByteString]
chunksOf n = unfoldr split
  where
    split bs = case C8.splitAt n bs of
      ("", _) -> Nothing
      chunks -> Just chunks

hexdump :: L.ByteString -> L.ByteString
hexdump = toLazyByteString . lazyByteStringHex

deriveTunnelId :: S.ByteString -> S.ByteString
deriveTunnelId secret = hkdfSha256 "" secret "\x02\x00\x00\x00" 16

deriveTunnelURL' :: L.ByteString -> Bytes -> L.ByteString
deriveTunnelURL' domain (Bytes secret) =
  let id' = deriveTunnelId secret
      hEX = C8.map toUpper $ toLazyByteString $ byteStringHex id'
   in "wss://" <> domain <> "/cable/new/" <> hEX

deriveTunnelURL :: Int -> Bytes -> String
deriveTunnelURL domain = C8.unpack . deriveTunnelURL' (fromMaybe "" (decodeDomain domain))

decodeDomain :: Int -> Maybe L.ByteString
decodeDomain domainId
  | domainId < 256 =
      if domainId >= 0 && domainId < length domains
        then Just (domains !! domainId)
        else Nothing
  | otherwise = Just $ decodeDomain' domainId
  where
    domains = ["cable.ua5v.com", "cable.auth.com"]

{--
  https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake_unittest.cc;drc=cb95e30fa939a18bc0845b57b0946a102b86cf9d;l=37
  266: cable.wufkweyy3uaxb.com
--}
decodeDomain' :: Int -> L.ByteString
decodeDomain' domainId =
  let name = build (result `unsafeShiftR` 2) (byteString "cable.")
      tld = [".com", ".org", ".net", ".info"] !! fromIntegral (result .&. 3)
   in toLazyByteString $ name <> byteString tld
  where
    templ =
      byteString (S.dropEnd 3 "caBLEv2 tunnel server domain\0\0\0")
        <> word8 (fromIntegral $ domainId .&. 0x00ff)
        <> word8 (fromIntegral $ (domainId .&. 0xff00) `shiftR` 8)
        --  // The input should be NUL-terminated, thus the trailing NUL in |templ| is
        --  // included here.
        <> word8 0
    digest = hashlazy @SHA256 (toLazyByteString templ)
    result =
      let w8s = take 8 $ ByteArray.unpack digest ++ repeat 0
       in (fromIntegral (w8s !! 7) `unsafeShiftL` 56) .|.
          (fromIntegral (w8s !! 6) `unsafeShiftL` 48) .|.
          (fromIntegral (w8s !! 5) `unsafeShiftL` 40) .|.
          (fromIntegral (w8s !! 4) `unsafeShiftL` 32) .|.
          (fromIntegral (w8s !! 3) `unsafeShiftL` 24) .|.
          (fromIntegral (w8s !! 2) `unsafeShiftL` 16) .|.
          (fromIntegral (w8s !! 1) `unsafeShiftL` 8)  .|.
          (fromIntegral (w8s !! 0)) :: Word64
    build 0 ret = ret
    build n ret =
      let ret' = ret <> word8 (base32Chars `S.index` fromIntegral (n .&. 31))
       in build (n `unsafeShiftR` 5) ret'
      where
        base32Chars = "abcdefghijklmnopqrstuvwxyz234567"
