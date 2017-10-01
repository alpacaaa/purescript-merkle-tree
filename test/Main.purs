module Test.Main where

import Crypto.Hash.MerkleTree as MerkleTree

import Prelude
import Control.Monad.Eff (Eff)
import Control.Monad.Eff.Console (CONSOLE)
import Control.Monad.Eff.Random (RANDOM)
import Control.Monad.Eff.Exception (EXCEPTION)


import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Test.QuickCheck (quickCheck)
import Test.QuickCheck.Arbitrary (class Arbitrary)
import Test.QuickCheck.Gen (chooseInt)

newtype MerkleTest = MerkleTest { size :: Int, leaf :: Int }

derive instance genericMerkleTest :: Generic MerkleTest _

instance showMerkleTest :: Show a => Show MerkleTest where
  show = genericShow

instance arbitraryMerkleTest :: Arbitrary MerkleTest where
  arbitrary = do
    size <- chooseInt 100 10000
    leaf <- chooseInt 100 size
    pure $ MerkleTest { size, leaf }

main :: Eff (console :: CONSOLE, random :: RANDOM, exception :: EXCEPTION) Unit
main = quickCheck \(MerkleTest { size, leaf }) ->
  MerkleTree.testMerkleProofN size leaf
