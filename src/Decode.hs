{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Decode where

import Control.Monad (foldM, guard)
import Data.Bifunctor (first)
import Data.Bits (shiftR)
import Data.ByteString.Builder (lazyByteString, toLazyByteString)
import Data.ByteString.Lazy (ByteString, pack)
import Data.ByteString.Lazy.Char8 qualified as C8
import Data.Char (isDigit)
import Data.List (isPrefixOf, unfoldr)
import Data.Word (Word64)
import Util (chunksOf)

parseFidoUrl :: String -> Either String ByteString
parseFidoUrl url
  | "FIDO:/" `isPrefixOf` url = go $ drop 6 url
  | otherwise = Left "should start with \"FIDO:/\""
  where
    go = \case
      "" -> Left "empty digits"
      u | not (all isDigit u) -> Left "contains non-digit characters"
      u -> let u' = C8.pack u in maybe (Left "invalid data") Right (digitsToBytes u')

digitsToBytes :: ByteString -> Maybe ByteString
digitsToBytes digits =
  let chunks = chunksOf 17 digits
      builder = foldM go mempty chunks
   in fmap toLazyByteString builder
  where
    go builder chunk = (\decoded -> builder <> lazyByteString decoded) <$> decode10 chunk

decode10 :: ByteString -> Maybe ByteString
decode10 bs = do
  (n :: Word64, _) <- first fromIntegral <$> C8.readInteger bs
  let size = remaining $ C8.length bs
  guard $ n `shiftR` (size * 8) == 0
  let w8s = take size $ unfoldr g n ++ repeat 0
  return $ pack w8s
  where
    g w = if w /= 0 then Just (fromIntegral w, w `shiftR` 8) else Nothing
    remaining 3 = 1
    remaining 5 = 2
    remaining 8 = 3
    remaining 10 = 4
    remaining 13 = 5
    remaining 15 = 6
    remaining 17 = 7
    -- not reached
    remaining _ = 0
