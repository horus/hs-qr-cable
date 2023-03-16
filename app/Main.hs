{-# LANGUAGE LambdaCase #-}

module Main (main) where

import Codec.CBOR.Pretty (prettyHexEnc)
import Codec.Serialise (DeserialiseFailure (..), deserialiseOrFail, encode)
import Decode (parseFidoUrl)
import System.Environment (getArgs, getProgName)
import Text.Pretty.Simple (pPrint, pPrintString)
import Types (fromTMap)
import Util (hexdump)

main :: IO ()
main =
  getArgs >>= \case
    [] -> do
      prog <- getProgName
      putStrLn $ "Usage: " ++ prog ++ " FIDO:/00112233445566778899..."
    (url : _) -> do
      putStrLn "=== Input ===\n"
      pPrint url
      putStrLn "\n=== CBOR bytes (hex) ===\n"
      case parseFidoUrl url of
        Right bytes -> do
          pPrint $ hexdump bytes
          putStrLn "\n=== CBOR decoded ==="
          output $ deserialiseOrFail bytes
        Left err -> putStrLn $ "Error decoding URL: " ++ err
  where
    output (Left (DeserialiseFailure off msg)) =
      putStrLn $ "\nCBOR deserialization failed at offset " ++ show off ++ ": " ++ msg
    output (Right decoded) = do
      pPrintString $ prettyHexEnc $ encode decoded
      putStrLn "\n=== Type ===\n"
      case fromTMap decoded of
        Right handshake -> pPrint handshake
        Left err -> putStrLn $ "Error parsing CBOR data: " ++ err
