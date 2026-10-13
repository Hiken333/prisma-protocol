//! Reed-Solomon FEC for PRISM (spec §2.3: 10+2 default).
//!
//! Encodes `k` data shards + `m` parity shards. Any `k` of `k+m` shards
//! recover the original block without retransmit.

use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;

pub const DEFAULT_K: usize = 10;
pub const DEFAULT_M: usize = 2;

#[derive(Debug, Error)]
pub enum FecError {
    #[error("invalid shard layout")]
    InvalidLayout,
    #[error("encode failed")]
    Encode,
    #[error("decode failed")]
    Decode,
    #[error("shard index out of range")]
    BadIndex,
}

/// One FEC block: `k` data + `m` parity shards of equal size.
pub struct FecBlock {
    k: usize,
    m: usize,
    _shard_size: usize,
    shards: Vec<Vec<u8>>,
}

impl FecBlock {
    /// Build a block from `k` equal-length data shards; parity is computed.
    pub fn encode(data_shards: Vec<Vec<u8>>) -> Result<Self, FecError> {
        Self::encode_with_params(DEFAULT_K, DEFAULT_M, data_shards)
    }

    pub fn encode_with_params(k: usize, m: usize, data_shards: Vec<Vec<u8>>) -> Result<Self, FecError> {
        if data_shards.len() != k || k == 0 {
            return Err(FecError::InvalidLayout);
        }
        let shard_size = data_shards[0].len();
        if !data_shards.iter().all(|s| s.len() == shard_size) {
            return Err(FecError::InvalidLayout);
        }
        let rs = ReedSolomon::new(k, m).map_err(|_| FecError::Encode)?;
        let mut shards = data_shards;
        for _ in 0..m {
            shards.push(vec![0u8; shard_size]);
        }
        rs.encode(&mut shards).map_err(|_| FecError::Encode)?;
        Ok(Self { k, m, _shard_size: shard_size, shards })
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn m(&self) -> usize {
        self.m
    }

    pub fn total_shards(&self) -> usize {
        self.k + self.m
    }

    pub fn shard(&self, index: usize) -> Result<&[u8], FecError> {
        self.shards.get(index).map(|s| s.as_slice()).ok_or(FecError::BadIndex)
    }

    /// Attempt recovery when some shards are missing (`None` entries).
    pub fn reconstruct(mut shards: Vec<Option<Vec<u8>>>, k: usize, m: usize) -> Result<Vec<u8>, FecError> {
        if shards.len() != k + m {
            return Err(FecError::InvalidLayout);
        }
        let rs = ReedSolomon::new(k, m).map_err(|_| FecError::Decode)?;
        rs.reconstruct(&mut shards).map_err(|_| FecError::Decode)?;
        let mut out = Vec::new();
        for i in 0..k {
            let s = shards[i].as_ref().ok_or(FecError::Decode)?;
            out.extend_from_slice(s);
        }
        Ok(out)
    }
}

/// Incremental FEC group assembly on the receive side.
pub struct FecGroupAssembler {
    k: usize,
    m: usize,
    shards: Vec<Option<Vec<u8>>>,
}

impl FecGroupAssembler {
    pub fn new(k: usize, m: usize) -> Self {
        Self {
            k,
            m,
            shards: vec![None; k + m],
        }
    }

    pub fn insert_shard(&mut self, index: usize, data: Vec<u8>) -> Result<(), FecError> {
        if index >= self.k + self.m {
            return Err(FecError::BadIndex);
        }
        self.shards[index] = Some(data);
        Ok(())
    }

    pub fn ready_to_decode(&self) -> bool {
        self.shards.iter().filter(|s| s.is_some()).count() >= self.k
    }

    pub fn try_reconstruct(&mut self) -> Result<Option<Vec<u8>>, FecError> {
        if !self.ready_to_decode() {
            return Ok(None);
        }
        let shards = std::mem::take(&mut self.shards);
        self.shards = vec![None; self.k + self.m];
        Ok(Some(FecBlock::reconstruct(shards, self.k, self.m)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_with_two_parity_only_loss() {
        let data: Vec<Vec<u8>> = (0..DEFAULT_K).map(|i| vec![i as u8; 64]).collect();
        let block = FecBlock::encode(data).unwrap();
        let mut shards: Vec<Option<Vec<u8>>> = (0..DEFAULT_K + DEFAULT_M)
            .map(|i| Some(block.shard(i).unwrap().to_vec()))
            .collect();
        // Lose two data shards — recover from parity.
        shards[0] = None;
        shards[3] = None;
        let recovered = FecBlock::reconstruct(shards, DEFAULT_K, DEFAULT_M).unwrap();
        assert_eq!(recovered.len(), DEFAULT_K * 64);
        for (i, chunk) in recovered.chunks(64).enumerate() {
            assert_eq!(chunk[0], i as u8);
        }
    }
}
