module Crypto.Hash.MerkleTree
  ( MerkleTree(..)
  , MerkleRoot(..)
  , MerkleNode(..)

  -- ** Constructors
  , mkMerkleTree
  , mkRootHash
  , mkLeafRootHash
  , emptyHash

  -- ** Merkle Proof
  , MerkleProof(..)
  , ProofList(..)
  , ProofElem(..)
  , Side(..)
  , merkleProof
  , validateMerkleProof

  -- ** Size
  , mtRoot
  , mtSize
  , mtHash
  , mtHeight

  -- ** Testing
  , testMerkleProofN
  ) where


-- https://pursuit.purescript.org/packages/purescript-decimals/3.1.0

import Prelude
import Control.Monad.Eff (Eff)
import Control.Monad.Eff.Console (CONSOLE, log)

-- import Data.Foldable (class Foldable)
-- import Data.Foldable as Foldable
-- import Data.Monoid (mempty)
import Crypto.Simple as Crypto
import Data.Int (even)
import Data.Int.Bits ((.&.), shl, shr)
import Data.List (List(..), (:))
import Data.List as List

newtype MerkleRoot a = MerkleRoot String

derive instance eqMerkleRoot :: Eq (MerkleRoot a)

data MerkleTree a
  = MerkleEmpty
  | MerkleTree Int (MerkleNode a)

data MerkleNode a
  = MerkleBranch {
      mRoot  :: MerkleRoot a
    , mLeft  :: MerkleNode a
    , mRight :: MerkleNode a
  }
  | MerkleLeaf {
      mRoot :: MerkleRoot a
    , mVal  :: a
  }

-- instance foldableMerkleTree :: Foldable MerkleTree where
--   foldr = Foldable.foldrDefault
--   foldl = Foldable.foldlDefault
--   foldMap _ MerkleEmpty      = mempty
--   foldMap f (MerkleTree _ n) = Foldable.foldMap f n
--
-- instance foldableMerkleNode :: Foldable MerkleNode where
--   foldr = Foldable.foldrDefault
--   foldl = Foldable.foldlDefault
--   foldMap f x = case x of
--     MerkleLeaf{mVal}            -> f mVal
--     MerkleBranch{mLeft, mRight} ->
--       Foldable.foldMap f mLeft `append` Foldable.foldMap f mRight


-- | Returns root of merkle tree.
mtRoot :: forall a. MerkleTree a -> MerkleRoot a
mtRoot MerkleEmpty         = emptyHash
mtRoot (MerkleTree _ node) = nodeRoot node


-- | Returns root of merkle tree root hashed.

mtHash :: forall a. MerkleTree a -> String
mtHash MerkleEmpty      = merkleHash ""
mtHash (MerkleTree _ x) = merkleHash value
  where
    (MerkleRoot value) = nodeRoot x

mtSize :: forall a. MerkleTree a -> Int
mtSize MerkleEmpty      = 0
mtSize (MerkleTree s _) = s

emptyHash :: forall a. MerkleRoot a
emptyHash = MerkleRoot (merkleHash "")

merkleHash :: String -> String
merkleHash = Crypto.hash Crypto.SHA256


-- | Merkle tree height
mtHeight :: Int -> Int
mtHeight ntx
  | ntx < 2 = 0
  | even ntx  = 1 + mtHeight (ntx `div` 2)
  | otherwise = mtHeight $ ntx + 1

-- | Merkle tree width
mtWidth
  :: Int -- ^ Number of transactions (leaf nodes).
  -> Int -- ^ Height at which we want to compute the width.
  -> Int -- ^ Width of the merkle tree.
mtWidth ntx h = (ntx + (1 `shl` h) - 1) `shr` h

-- | Return the largest power of two such that it's smaller than n.
powerOfTwo :: Int -> Int
powerOfTwo n
   | n .&. (n - 1) == 0 = n `shr` 1
   | otherwise = go n
 where
    go w = if w .&. (w - 1) == 0 then w else go (w .&. (w - 1))


-------------------------------------------------------------------------------
-- Constructors
-------------------------------------------------------------------------------

mkLeaf :: String -> MerkleNode String
mkLeaf a =
  MerkleLeaf
  { mRoot: mkLeafRootHash a
  , mVal : a
  }

mkLeafRootHash :: String -> MerkleRoot String
mkLeafRootHash a = MerkleRoot $ merkleHash ("0" <> a)

nodeRoot :: forall a. MerkleNode a -> MerkleRoot a
nodeRoot (MerkleBranch { mRoot }) = mRoot
nodeRoot (MerkleLeaf { mRoot })   = mRoot

mkBranch :: forall a. MerkleNode a -> MerkleNode a -> MerkleNode a
mkBranch a b =
  MerkleBranch
  { mLeft : a
  , mRight: b
  , mRoot : mkRootHash (nodeRoot a) (nodeRoot b)
  }

mkRootHash :: forall a. MerkleRoot a -> MerkleRoot a -> MerkleRoot a
mkRootHash (MerkleRoot l) (MerkleRoot r) = MerkleRoot $ merkleHash $ ("1" <> l <> r)

-- | Smart constructor for 'MerkleTree'.
mkMerkleTree :: List String -> MerkleTree String
mkMerkleTree Nil = MerkleEmpty
mkMerkleTree ls  = MerkleTree lsLen (go lsLen ls)
  where
    lsLen              = List.length ls
    go _  (Cons x Nil) = mkLeaf x
    go len xs = mkBranch (go i l) (go (len - i) r)
      where
        i = powerOfTwo len
        {l, r} = { l: List.take i xs, r: List.drop i xs }

-------------------------------------------------------------------------------
-- Merkle Proofs
-------------------------------------------------------------------------------

type ProofList a = List (ProofElem a)

newtype MerkleProof a = MerkleProof (ProofList a)

data ProofElem a = ProofElem
  { nodeRoot    :: MerkleRoot a
  , siblingRoot :: MerkleRoot a
  , nodeSide    :: Side
  }

data Side = L | R

-- | Construct a merkle tree proof of inclusion
-- Walks the entire tree recursively, building a list of "proof elements"
-- that are comprised of the current node's root and it's sibling's root,
-- and whether it is the left or right sibling (this is necessary to determine
-- the order in which to hash each proof element root and it's sibling root).
-- The list is ordered such that the for each element, the next element in
-- the list is the proof element corresponding to the node's parent node.
merkleProof :: forall a. MerkleTree a -> MerkleRoot a -> MerkleProof a
merkleProof MerkleEmpty _ = MerkleProof Nil
merkleProof (MerkleTree _ rootNode) leafRoot = MerkleProof $ constructPath Nil rootNode
  where
    constructPath :: (ProofList a) -> MerkleNode a -> (ProofList a)
    constructPath pElems (MerkleLeaf leaf)
      | leafRoot == leaf.mRoot = pElems
      | otherwise              = Nil
    constructPath pElems (MerkleBranch branch) = lPath <> rPath
      where
        bRoot = branch.mRoot
        ln    = branch.mLeft
        rn    = branch.mRight
        lProofElem = ProofElem
          { nodeRoot: (nodeRoot ln), siblingRoot: (nodeRoot rn), nodeSide: L }
        rProofElem = ProofElem
          { nodeRoot: (nodeRoot rn), siblingRoot: (nodeRoot ln), nodeSide: R }

        lPath = constructPath (lProofElem:pElems) ln
        rPath = constructPath (rProofElem:pElems) rn

-- | Validate a merkle tree proof of inclusion
validateMerkleProof :: forall a. MerkleProof a ->  MerkleRoot a -> MerkleRoot a -> Boolean
validateMerkleProof (MerkleProof proofElems) treeRoot leafRoot =
  validate proofElems leafRoot
  where
    validate :: ProofList a -> MerkleRoot a -> Boolean
    validate Nil proofRoot = proofRoot == treeRoot
    validate (Cons pElem pElems) proofRoot =
      let
        (ProofElem proof) = pElem
      in
      if proofRoot /= proof.nodeRoot then
        false
      else
        validate pElems (hashProofElem pElem)

    hashProofElem :: ProofElem a -> MerkleRoot a
    hashProofElem (ProofElem proof) =
      case proof.nodeSide of
        L -> mkRootHash proof.nodeRoot proof.siblingRoot
        R -> mkRootHash proof.siblingRoot proof.nodeRoot



main :: forall e. Eff (console :: CONSOLE | e) Unit
main = do
  -- Does the proof prove that `mleaf` exists in `mtree`?
  log $ show $ validateMerkleProof proof (mtRoot mtree) mleaf
  where
    -- Build a merkle tree from a list of data
    mtree = mkMerkleTree $ List.fromFoldable ["tx1", "tx2", "tx3"]
    -- Construct merkle proof that a leaf exists in `merkleTree`
    mleaf = mkLeafRootHash "tx2"
    proof = merkleProof mtree mleaf



testMerkleProofN :: Int -> Int -> Boolean
testMerkleProofN size leaf =
  let
      input = List.range 1 size
      mtree = mkMerkleTree $ map show input
      randLeaf = mkLeafRootHash $ show leaf
      proof = merkleProof mtree randLeaf
  in
  validateMerkleProof proof (mtRoot mtree) randLeaf
