{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Codec.CBOR.Pretty (prettyHexEnc)
import Codec.Serialise (DeserialiseFailure (..), deserialiseOrFail, encode)
import Control.Monad (forM_)
import Decode (parseFidoUrl)
import System.Environment (getArgs, getProgName)
import Text.Pretty.Simple (pPrint, pPrintString)
import Tunnel (newTunnel)
import Types (Handshake (secret), fromHeader, fromTMap)
import Util

main :: IO ()
main =
  getArgs >>= \case
    [] -> do
      prog <- getProgName
      putStrLn $ "Usage: " ++ prog ++ " FIDO:/00112233445566778899..."
    (url : _) -> do
      putStrLn "# caBLEv2 Initiator FIDO:/ URL Decoder"
      putStrLn "## Input"
      pPrint url
      putStrLn "## CBOR data"
      putStrLn "### CBOR bytes (hex)"
      case parseFidoUrl url of
        Right bytes -> do
          pPrint $ hexdump bytes
          putStrLn "### CBOR decoded"
          output $ deserialiseOrFail bytes
        Left err -> putStrLn $ "Error decoding URL: " ++ err
  where
    output (Left (DeserialiseFailure off msg)) =
      putStrLn $ "CBOR deserialization failed at offset " ++ show off ++ ": " ++ msg
    output (Right decoded) = do
      putStr "```"
      pPrintString $ prettyHexEnc $ encode decoded
      putStrLn "```"
      putStrLn "## Type"
      case fromTMap decoded of
        Right handshake -> do
          putStrLn "```haskell"
          pPrint handshake
          putStrLn "```"
          putStrLn "## Derived Tunnel URL examples"
          showTunnel (secret handshake)
        Left err -> putStrLn $ "Error parsing CBOR data: " ++ err
    showTunnel s = do
      forM_ [(0, "Google"), (1, "Apple"), (0x03bb, "\x03bb")] $ \(i, provider) -> do
        putStr $ "- " ++ provider ++ ": "
        let Just domain = decodeDomain i
        pPrint $ deriveTunnelURL domain s
      let target = deriveTunnelURL' 0 s
      putStrLn "### Try connecting to a new tunnel via Google"
      headers <- newTunnel target
      putStrLn "#### Phony EID"
      let Just routingId = lookup "X-caBLE-Routing-Id" headers
          Just eid = fromHeader routingId
      putStrLn "```haskell"
      pPrint eid
      putStrLn "```"
