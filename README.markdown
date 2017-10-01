
# purescript-merkle-tree

```haskell
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
```
