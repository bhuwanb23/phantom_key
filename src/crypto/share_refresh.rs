//! Proactive Share Refresh
//!
//! This module implements epoch-based share refresh to provide
//! forward secrecy. Even if an adversary compromises shares,
//! they can only use them until the next refresh.

use super::{
    group::GroupScalar,
    dkg::{DKG, PartyContribution, DkgError},
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::thread;
use std::ops::Deref;

/// Error type for share refresh operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum ShareRefreshError {
    #[error("DKG error: {0}")]
    DkgError(#[from] DkgError),
    #[error("Share refresh already in progress")]
    RefreshInProgress,
    #[error("Old shares not available for epoch {0}")]
    OldSharesUnavailable(u64),
    #[error("Verification period not elapsed for epoch {0}")]
    VerificationPeriodNotElapsed(u64),
}

/// Epoch information
#[derive(Debug, Clone)]
pub struct EpochInfo {
    /// Epoch number
    pub epoch: u64,
    /// When this epoch started
    pub start_time: Instant,
    /// Shares for this epoch
    pub shares: Vec<GroupScalar>,
}

impl EpochInfo {
    pub fn new(epoch: u64, shares: Vec<GroupScalar>) -> Self {
        Self {
            epoch,
            start_time: Instant::now(),
            shares,
        }
    }
}

/// Share manager with epoch-based refresh
///
/// This manager:
/// - Tracks current epoch and shares
/// - Stores old shares temporarily for verification
/// - Automatically destroys old shares after verification period
/// - Provides thread-safe access to shares
pub struct ShareManager {
    /// Current epoch
    current_epoch: u64,
    /// Current epoch info
    current_info: EpochInfo,
    /// Old epochs (epoch -> EpochInfo)
    old_epochs: HashMap<u64, EpochInfo>,
    /// DKG instance
    dkg: DKG,
    /// Duration of each epoch
    epoch_duration: Duration,
    /// How long to keep old shares for verification
    verification_period: Duration,
    /// Last refresh time
    last_refresh: Instant,
    /// Is refresh in progress?
    refresh_in_progress: bool,
}

impl ShareManager {
    /// Create a new share manager
    pub fn new(
        parties: usize,
        threshold: usize,
        epoch_duration: Duration,
        verification_period: Duration,
    ) -> Result<Self, ShareRefreshError> {
        let dkg = DKG::new(parties, threshold)?;
        
        // Initialize with epoch 0
        let mut manager = Self {
            current_epoch: 0,
            current_info: EpochInfo::new(0, vec![GroupScalar::zero(); parties]),
            old_epochs: HashMap::new(),
            dkg,
            epoch_duration,
            verification_period,
            last_refresh: Instant::now(),
            refresh_in_progress: false,
        };
        
        // Initialize with first DKG
        manager.initialize()?;
        
        Ok(manager)
    }
    
    /// Initialize with first DKG
    pub fn initialize(&mut self) -> Result<(), ShareRefreshError> {
        // Generate initial contributions
        let contributions: Vec<PartyContribution> = (0..self.dkg.parties)
            .map(|i| self.dkg.generate_contribution(i).unwrap())
            .collect();
        
        // Combine to get initial shares
        let shares = self.dkg.combine_contributions(&contributions)?;
        
        // Update current epoch
        self.current_info = EpochInfo::new(self.current_epoch, shares);
        self.last_refresh = Instant::now();
        
        Ok(())
    }
    
    /// Get the current epoch
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    
    /// Get the current epoch info
    pub fn current_epoch_info(&self) -> &EpochInfo {
        &self.current_info
    }
    
    /// Get share for current epoch
    pub fn get_share(&self, party_id: usize) -> Option<GroupScalar> {
        self.current_info.shares.get(party_id).cloned()
    }
    
    /// Get share for a specific epoch (for verification)
    pub fn get_epoch_share(&self, epoch: u64, party_id: usize) -> Option<GroupScalar> {
        if epoch == self.current_epoch {
            return self.get_share(party_id);
        }
        
        self.old_epochs.get(&epoch)
            .and_then(|info| info.shares.get(party_id).cloned())
    }
    
    /// Get all shares for current epoch
    pub fn get_all_shares(&self) -> &[GroupScalar] {
        &self.current_info.shares
    }
    
    /// Check if share refresh is needed
    pub fn needs_refresh(&self) -> bool {
        self.last_refresh.elapsed() >= self.epoch_duration
    }
    
    /// Refresh shares for a new epoch
    ///
    /// This generates new shares without reconstructing the old secret.
    /// The new shares are for a new random secret, but the public key
    /// can be updated to maintain consistency.
    pub fn refresh(&mut self) -> Result<(), ShareRefreshError> {
        if self.refresh_in_progress {
            return Err(ShareRefreshError::RefreshInProgress);
        }
        
        self.refresh_in_progress = true;
        
        // Store current epoch in old_epochs
        self.old_epochs.insert(self.current_epoch, self.current_info.clone());
        
        // Increment epoch
        self.current_epoch += 1;
        
        // Generate new contributions
        let contributions: Vec<PartyContribution> = (0..self.dkg.parties)
            .map(|i| self.dkg.generate_contribution(i).unwrap())
            .collect();
        
        // Combine to get new shares
        let shares = self.dkg.combine_contributions(&contributions)?;
        
        // Update current epoch
        self.current_info = EpochInfo::new(self.current_epoch, shares);
        self.last_refresh = Instant::now();
        self.refresh_in_progress = false;
        
        // Cleanup old epochs that have passed verification period
        self.cleanup_old_epochs();
        
        Ok(())
    }
    
    /// Cleanup old epochs that have passed verification period
    pub fn cleanup_old_epochs(&mut self) {
        let now = Instant::now();
        
        self.old_epochs.retain(|epoch, info| {
            // Keep if verification period hasn't elapsed
            now.duration_since(info.start_time) < self.verification_period
        });
    }
    
    /// Get public key for current epoch
    pub fn get_public_key(&self) -> GroupElement {
        // In a real implementation, we'd need to track public keys per epoch
        // For now, we'll just return a placeholder
        // This would be the sum of all C_{i,0} from the DKG
        
        // For simplicity, we'll compute it from current shares
        // S = Σ s_i·G
        use super::group::GroupElement;
        self.current_info.shares.iter()
            .fold(GroupElement::identity(), |acc, s| acc + GroupElement::generator().multiply(s))
    }
    
    /// Get public key for a specific epoch
    pub fn get_epoch_public_key(&self, epoch: u64) -> Option<GroupElement> {
        if epoch == self.current_epoch {
            return Some(self.get_public_key());
        }
        
        self.old_epochs.get(&epoch)
            .map(|info| {
                info.shares.iter()
                    .fold(GroupElement::identity(), |acc, s| acc + GroupElement::generator().multiply(s))
            })
    }
    
    /// Get all old epochs
    pub fn get_old_epochs(&self) -> Vec<&EpochInfo> {
        self.old_epochs.values().collect()
    }
    
    /// Check if an epoch's shares are still available
    pub fn has_epoch(&self, epoch: u64) -> bool {
        if epoch == self.current_epoch {
            return true;
        }
        self.old_epochs.contains_key(&epoch)
    }
    
    /// Get epoch duration
    pub fn epoch_duration(&self) -> Duration {
        self.epoch_duration
    }
    
    /// Get verification period
    pub fn verification_period(&self) -> Duration {
        self.verification_period
    }
}

/// Thread-safe wrapper for ShareManager
pub struct SyncShareManager(Arc<Mutex<ShareManager>>);

impl SyncShareManager {
    pub fn new(
        parties: usize,
        threshold: usize,
        epoch_duration: Duration,
        verification_period: Duration,
    ) -> Result<Self, ShareRefreshError> {
        ShareManager::new(parties, threshold, epoch_duration, verification_period)
            .map(|m| Self(Arc::new(Mutex::new(m))))
    }
    
    pub fn get_share(&self, party_id: usize) -> Option<GroupScalar> {
        self.0.lock().unwrap().get_share(party_id)
    }
    
    pub fn get_epoch_share(&self, epoch: u64, party_id: usize) -> Option<GroupScalar> {
        self.0.lock().unwrap().get_epoch_share(epoch, party_id)
    }
    
    pub fn current_epoch(&self) -> u64 {
        self.0.lock().unwrap().current_epoch()
    }
    
    pub fn needs_refresh(&self) -> bool {
        self.0.lock().unwrap().needs_refresh()
    }
    
    pub fn refresh(&self) -> Result<(), ShareRefreshError> {
        self.0.lock().unwrap().refresh()
    }
    
    pub fn get_public_key(&self) -> GroupElement {
        self.0.lock().unwrap().get_public_key()
    }
}

impl Deref for SyncShareManager {
    type Target = Arc<Mutex<ShareManager>>;
    
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Auto-refresh manager
///
/// This spawns a background thread that automatically refreshes
/// shares on a schedule.
pub struct AutoRefresh {
    share_manager: Arc<Mutex<ShareManager>>,
    refresh_interval: Duration,
    stop_signal: Arc<Mutex<bool>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl AutoRefresh {
    pub fn new(
        share_manager: Arc<Mutex<ShareManager>>,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            share_manager,
            refresh_interval,
            stop_signal: Arc::new(Mutex::new(false)),
            thread_handle: None,
        }
    }
    
    /// Start the auto-refresh thread
    pub fn start(&mut self) {
        let share_manager = self.share_manager.clone();
        let stop_signal = self.stop_signal.clone();
        let interval = self.refresh_interval;
        
        self.thread_handle = Some(thread::spawn(move || {
            loop {
                // Check if we should stop
                if *stop_signal.lock().unwrap() {
                    break;
                }
                
                // Sleep for the interval
                thread::sleep(interval);
                
                // Check if refresh is needed
                let mut manager = share_manager.lock().unwrap();
                if manager.needs_refresh() {
                    let _ = manager.refresh();
                }
            }
        }));
    }
    
    /// Stop the auto-refresh thread
    pub fn stop(&mut self) {
        *self.stop_signal.lock().unwrap() = true;
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for AutoRefresh {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Epoch-based key derivation
///
/// This binds derived keys to specific epochs, ensuring that
/// even if old shares are compromised, they can't be used
/// to derive current keys.
pub struct EpochKeyDerivation {
    share_manager: Arc<Mutex<ShareManager>>,
}

impl EpochKeyDerivation {
    pub fn new(share_manager: Arc<Mutex<ShareManager>>) -> Self {
        Self { share_manager }
    }
    
    /// Derive a key bound to the current epoch
    ///
    /// The key is derived as: HKDF(epoch || secret_share || context)
    /// This ensures that keys from different epochs are different.
    pub fn derive_epoch_key(
        &self,
        party_id: usize,
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, ShareRefreshError> {
        let manager = self.share_manager.lock().unwrap();
        let share = manager.get_share(party_id)
            .ok_or(ShareRefreshError::OldSharesUnavailable(manager.current_epoch()))?;
        
        let epoch = manager.current_epoch();
        
        // Derive key: HKDF(epoch || share || context)
        use sha2::{Sha256, Digest};
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        
        let mut hkdf = HmacSha256::new_from_slice(&[])
            .expect("HMAC can take key of any size");
        
        // Input key material: epoch || share || context
        hkdf.update(&epoch.to_be_bytes());
        hkdf.update(&share.to_bytes());
        hkdf.update(context);
        
        let prk = hkdf.finalize().into_bytes();
        
        // Expand
        let mut hkdf = HmacSha256::new_from_slice(&prk);
        hkdf.update(&[0x01]);
        let mut okm = hkdf.finalize().into_bytes();
        okm.truncate(output_len);
        
        Ok(okm)
    }
    
    /// Derive a key bound to a specific epoch
    pub fn derive_epoch_key_for_epoch(
        &self,
        epoch: u64,
        party_id: usize,
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, ShareRefreshError> {
        let manager = self.share_manager.lock().unwrap();
        let share = manager.get_epoch_share(epoch, party_id)
            .ok_or(ShareRefreshError::OldSharesUnavailable(epoch))?;
        
        // Derive key: HKDF(epoch || share || context)
        use sha2::{Sha256, Digest};
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        
        let mut hkdf = HmacSha256::new_from_slice(&[])
            .expect("HMAC can take key of any size");
        
        hkdf.update(&epoch.to_be_bytes());
        hkdf.update(&share.to_bytes());
        hkdf.update(context);
        
        let prk = hkdf.finalize().into_bytes();
        
        let mut hkdf = HmacSha256::new_from_slice(&prk);
        hkdf.update(&[0x01]);
        let mut okm = hkdf.finalize().into_bytes();
        okm.truncate(output_len);
        
        Ok(okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_share_manager_creation() {
        let manager = ShareManager::new(
            5,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(300),
        );
        
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        
        assert_eq!(manager.current_epoch(), 0);
        assert_eq!(manager.get_all_shares().len(), 5);
    }
    
    #[test]
    fn test_share_manager_get_share() {
        let mut manager = ShareManager::new(
            5,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(300),
        ).unwrap();
        
        // Get share for party 0
        let share = manager.get_share(0);
        assert!(share.is_some());
        
        // Get share for party 4
        let share = manager.get_share(4);
        assert!(share.is_some());
        
        // Get share for invalid party
        let share = manager.get_share(5);
        assert!(share.is_none());
    }
    
    #[test]
    fn test_share_manager_refresh() {
        let mut manager = ShareManager::new(
            5,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(300),
        ).unwrap();
        
        let old_shares = manager.get_all_shares().clone();
        
        // Refresh
        manager.refresh().unwrap();
        
        // Epoch should increment
        assert_eq!(manager.current_epoch(), 1);
        
        // Shares should be different
        let new_shares = manager.get_all_shares();
        assert_ne!(&old_shares[..], new_shares);
        
        // Old shares should be available
        assert!(manager.has_epoch(0));
        
        // Can get old share
        let old_share = manager.get_epoch_share(0, 0);
        assert!(old_share.is_some());
    }
    
    #[test]
    fn test_share_manager_multiple_refreshes() {
        let mut manager = ShareManager::new(
            5,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(300),
        ).unwrap();
        
        // Multiple refreshes
        for epoch in 1..=5 {
            manager.refresh().unwrap();
            assert_eq!(manager.current_epoch(), epoch);
            assert!(manager.has_epoch(epoch - 1));
        }
        
        // Should have epochs 0-4 in old_epochs
        assert_eq!(manager.get_old_epochs().len(), 5);
    }
    
    #[test]
    fn test_share_manager_public_key() {
        let manager = ShareManager::new(
            5,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(300),
        ).unwrap();
        
        let public_key = manager.get_public_key();
        
        // Public key should not be identity
        assert!(!public_key.is_identity());
    }
    
    #[test]
    fn test_sync_share_manager() {
        let manager = SyncShareManager::new(
            5,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(300),
        ).unwrap();
        
        // Get share
        let share = manager.get_share(0);
        assert!(share.is_some());
        
        // Get current epoch
        let epoch = manager.current_epoch();
        assert_eq!(epoch, 0);
    }
    
    #[test]
    fn test_epoch_key_derivation() {
        let manager = Arc::new(Mutex::new(
            ShareManager::new(
                5,
                3,
                Duration::from_secs(3600),
                Duration::from_secs(300),
            ).unwrap()
        ));
        
        let key_derivation = EpochKeyDerivation::new(manager.clone());
        
        // Derive key for current epoch
        let key1 = key_derivation.derive_epoch_key(0, b"test context", 32).unwrap();
        assert_eq!(key1.len(), 32);
        
        // Same inputs should produce same output
        let key2 = key_derivation.derive_epoch_key(0, b"test context", 32).unwrap();
        assert_eq!(key1, key2);
        
        // Different context should produce different output
        let key3 = key_derivation.derive_epoch_key(0, b"different context", 32).unwrap();
        assert_ne!(key1, key3);
        
        // Different party should produce different output
        let key4 = key_derivation.derive_epoch_key(1, b"test context", 32).unwrap();
        assert_ne!(key1, key4);
    }
    
    #[test]
    fn test_epoch_key_derivation_different_epochs() {
        let manager = Arc::new(Mutex::new(
            ShareManager::new(
                5,
                3,
                Duration::from_secs(3600),
                Duration::from_secs(300),
            ).unwrap()
        ));
        
        let key_derivation = EpochKeyDerivation::new(manager.clone());
        
        // Derive key for epoch 0
        let key0 = key_derivation.derive_epoch_key(0, b"test", 32).unwrap();
        
        // Refresh to epoch 1
        {
            let mut manager = manager.lock().unwrap();
            manager.refresh().unwrap();
        }
        
        // Derive key for epoch 1
        let key1 = key_derivation.derive_epoch_key(0, b"test", 32).unwrap();
        
        // Keys should be different because epoch changed
        assert_ne!(key0, key1);
        
        // Can still derive key for epoch 0
        let key0_again = key_derivation.derive_epoch_key_for_epoch(0, 0, b"test", 32).unwrap();
        assert_eq!(key0, key0_again);
    }
    
    #[test]
    fn test_auto_refresh() {
        let manager = Arc::new(Mutex::new(
            ShareManager::new(
                5,
                3,
                Duration::from_millis(100), // Short epoch for testing
                Duration::from_secs(300),
            ).unwrap()
        ));
        
        let mut auto_refresh = AutoRefresh::new(manager.clone(), Duration::from_millis(50));
        
        // Start auto-refresh
        auto_refresh.start();
        
        // Wait for refresh to happen
        std::thread::sleep(Duration::from_millis(200));
        
        // Check that epoch has incremented
        let manager = manager.lock().unwrap();
        assert!(manager.current_epoch() >= 1);
        
        // Stop auto-refresh
        auto_refresh.stop();
    }
}
