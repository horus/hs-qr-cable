{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Tunnel where

import Control.Exception (bracket)
import Data.Attoparsec.ByteString qualified as A
import Data.ByteString qualified as S
import Data.ByteString.Builder
import Data.ByteString.Char8 (unpack)
import Data.ByteString.Internal (c2w)
import Data.ByteString.Lazy qualified as L
import Data.CaseInsensitive qualified as CI
import Data.List (isPrefixOf)
import Network.HTTP.Client as HTTP
import Network.HTTP.Client.Internal
import Network.HTTP.Client.TLS (newTlsManager)
import Network.WebSockets (Headers, RequestHead (..), ResponseHead (..))
import Network.WebSockets.Client (createRequest, defaultProtocol)
import Network.WebSockets.Stream qualified as Stream
import Text.Pretty.Simple (pPrint)

-- https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_authenticator.cc;drc=cb95e30fa939a18bc0845b57b0946a102b86cf9d;l=288

newTunnel :: String -> IO Headers
newTunnel url = secureWebSocket url $ \host path stream -> do
  request <- createRequest defaultProtocol host path True [("Sec-WebSocket-Protocol", "fido.cable"), ("Origin", "wss://" <> host)]
  putStrLn "```haskell"
  pPrint request
  putStrLn "```"
  Stream.write stream $ encodeRequestHead request
  Stream.parse stream decodeResponseHead >>= \case
    Just rh@(ResponseHead _ _ headers) -> do
      putStrLn "```haskell"
      pPrint rh
      putStrLn "```"
      -- Stream.parseBin stream (Get.getByteString 0) >>= print
      return headers
    _ -> error "internal error"

secureWebSocket :: String -> (S.ByteString -> S.ByteString -> Stream.Stream -> IO a) -> IO a
secureWebSocket url streamer
  | "wss://" `isPrefixOf` url = do
      let req = parseRequest_ $ "http" ++ drop 2 url
      mgr <- newTlsManager
      withConnection req mgr $ \c -> do
        let r = (\bs -> if S.null bs then Nothing else Just bs) <$> connectionRead c
            w = maybe (connectionClose c) (connectionWrite c . L.toStrict)
        bracket (Stream.makeStream r w) Stream.close $ streamer (host req) (path req)
  | otherwise = error "invalid tunnel url"

encodeRequestHead :: RequestHead -> L.ByteString
encodeRequestHead (RequestHead path headers _) =
  toLazyByteString $
    "GET "
      <> byteString path
      <> " HTTP/1.1\r\n"
      <> foldMap pairwise headers
      <> "\r\n"
  where
    pairwise (k, v) = byteString (CI.original k) <> ": " <> byteString v <> "\r\n"

decodeResponseHead :: A.Parser ResponseHead
decodeResponseHead =
  ResponseHead
    <$> fmap (read . unpack) code
    <*> message
    <*> A.manyTill decodeHeaderLine newline
  where
    space = A.word8 (c2w ' ')
    newline = A.string "\r\n"
    code = A.string "HTTP/1.1" *> space *> A.takeWhile1 digit <* space
    digit x = x >= c2w '0' && x <= c2w '9'
    message = A.takeWhile (/= c2w '\r') <* newline

decodeHeaderLine :: A.Parser (CI.CI S.ByteString, S.ByteString)
decodeHeaderLine =
  (,)
    <$> (CI.mk <$> A.takeWhile1 (/= c2w ':'))
    <* A.word8 (c2w ':')
    <* A.option (c2w ' ') (A.word8 (c2w ' '))
    <*> A.takeWhile (/= c2w '\r')
    <* A.string "\r\n"
