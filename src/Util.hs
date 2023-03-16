{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Util where

import Data.ByteString qualified as S
import Data.ByteString.Builder
import Data.ByteString.Lazy qualified as L
import Data.ByteString.Lazy.Char8 qualified as C8
import Data.Int (Int64)
import Data.List (unfoldr)

chunksOf :: Int64 -> L.ByteString -> [L.ByteString]
chunksOf n = unfoldr split
  where
    split bs = case C8.splitAt n bs of
      ("", _) -> Nothing
      chunks -> Just chunks

hexdump :: L.ByteString -> L.ByteString
hexdump = toLazyByteString . lazyByteStringHex

hexdump' :: S.ByteString -> L.ByteString
hexdump' = toLazyByteString . byteStringHex

-- -- from either:Data.Either.Combinators
-- maybeToRight :: b -> Maybe a -> Either b a
-- maybeToRight _ (Just x) = Right x
-- maybeToRight y Nothing  = Left y
