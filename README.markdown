
# purescript-merkle-tree

Merkle Tree data structure.

This is mostly a direct port of the amazing Haskell library [adjoint-io/merkle-tree](https://github.com/adjoint-io/merkle-tree) to Purescript.



### Example

```haskell
import Data.List as List
import Crypto.Hash.MerkleTree as MT

main = do
  -- Does the proof prove that `mleaf` exists in `mtree`?
  log $ show $ MT.validateMerkleProof proof (MT.mtRoot mtree) mleaf
  where
    -- Build a merkle tree from a list of data
    mtree = MT.mkMerkleTree $ List.fromFoldable ["tx1", "tx2", "tx3"]
    -- Construct merkle proof that a leaf exists in `merkleTree`
    mleaf = MT.mkLeafRootHash "tx2"
    proof = MT.merkleProof mtree mleaf
```
