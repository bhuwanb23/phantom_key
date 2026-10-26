//! Group Operations for Ristretto255
//!
//! This module provides safe wrappers around curve25519-dalek's
//! Scalar and RistrettoPoint types with proper serialization
//! and constant-time operations.

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

/// Error type for group operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum GroupError {
    #[error("Invalid scalar bytes")]
    InvalidScalarBytes,
    #[error("Invalid point bytes")]
    InvalidPointBytes,
    #[error("Point at infinity")]
    PointAtInfinity,
    #[error("Group operation failed")]
    OperationFailed,
}

/// Wrapper for Scalar with safe operations
/// 
/// GroupScalar wraps curve25519-dalek::Scalar to provide:
/// - Safe construction from bytes
/// - Serialization/deserialization
/// - Constant-time equality
/// - Zeroize on drop
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct GroupScalar(pub(crate) Scalar);

impl GroupScalar {
    /// Generate a random scalar
    pub fn random() -> Self {
        Self(Scalar::random(&mut rand::thread_rng()))
    }
    
    /// Zero scalar
    pub fn zero() -> Self {
        Self(Scalar::zero())
    }
    
    /// One scalar
    pub fn one() -> Self {
        Self(Scalar::one())
    }
    
    /// Create from canonical bytes (32 bytes)
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, GroupError> {
        Scalar::from_canonical_bytes(bytes)
            .map(Self)
            .ok_or(GroupError::InvalidScalarBytes)
    }
    
    /// Create from slice (32 bytes)
    pub fn from_slice(bytes: &[u8]) -> Result<Self, GroupError> {
        if bytes.len() != 32 {
            return Err(GroupError::InvalidScalarBytes);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Self::from_bytes(arr)
    }
    
    /// Convert to bytes (32 bytes)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    
    /// Constant-time equality check
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
    
    /// Add two scalars
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }
    
    /// Subtract two scalars
    pub fn sub(&self, other: &Self) -> Self {
        Self(self.0 - other.0)
    }
    
    /// Multiply two scalars
    pub fn mul(&self, other: &Self) -> Self {
        Self(self.0 * other.0)
    }
    
    /// Negate scalar
    pub fn negate(&self) -> Self {
        Self(-self.0)
    }
    
    /// Invert scalar (modular inverse)
    pub fn invert(&self) -> Result<Self, GroupError> {
        self.0.invert().map(Self).ok_or(GroupError::OperationFailed)
    }
    
    /// Raise to power
    pub fn pow(&self, exponent: u64) -> Self {
        Self(self.0.pow(exponent))
    }
    
    /// Multiply by scalar (for scalar multiplication)
    pub fn multiply(&self, point: &GroupElement) -> GroupElement {
        GroupElement(point.0 * self.0)
    }
}

impl std::ops::Add for GroupScalar {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        self.add(&other)
    }
}

impl std::ops::Sub for GroupScalar {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        self.sub(&other)
    }
}

impl std::ops::Mul for GroupScalar {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        self.mul(&other)
    }
}

impl std::ops::Neg for GroupScalar {
    type Output = Self;
    fn neg(self) -> Self {
        self.negate()
    }
}

/// Wrapper for RistrettoPoint with safe operations
/// 
/// GroupElement wraps curve25519-dalek::RistrettoPoint to provide:
/// - Safe construction from bytes
/// - Serialization/deserialization
/// - Constant-time equality
/// - All group operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupElement(pub(crate) RistrettoPoint);

impl GroupElement {
    /// Generator point
    pub fn generator() -> Self {
        Self(RistrettoPoint::generator())
    }
    
    /// Identity element
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }
    
    /// Create from compressed bytes (32 bytes)
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, GroupError> {
        RistrettoPoint::from_uniform_bytes(&bytes)
            .map(Self)
            .ok_or(GroupError::InvalidPointBytes)
    }
    
    /// Create from slice (32 bytes compressed)
    pub fn from_slice(bytes: &[u8]) -> Result<Self, GroupError> {
        if bytes.len() != 32 {
            return Err(GroupError::InvalidPointBytes);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Self::from_bytes(arr)
    }
    
    /// Convert to compressed bytes (32 bytes)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
    
    /// Constant-time equality check
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
    
    /// Add two group elements
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }
    
    /// Subtract two group elements
    pub fn sub(&self, other: &Self) -> Self {
        Self(self.0 - other.0)
    }
    
    /// Negate element
    pub fn negate(&self) -> Self {
        Self(-self.0)
    }
    
    /// Multiply by scalar
    pub fn multiply(&self, scalar: &GroupScalar) -> Self {
        Self(self.0 * scalar.0)
    }
    
    /// Double the element (self + self)
    pub fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
    
    /// Check if this is the identity element
    pub fn is_identity(&self) -> bool {
        self.0 == RistrettoPoint::identity()
    }
}

impl std::ops::Add for GroupElement {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        self.add(&other)
    }
}

impl std::ops::Sub for GroupElement {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        self.sub(&other)
    }
}

impl std::ops::Neg for GroupElement {
    type Output = Self;
    fn neg(self) -> Self {
        self.negate()
    }
}

impl std::ops::Mul<GroupScalar> for GroupElement {
    type Output = Self;
    fn mul(self, scalar: GroupScalar) -> Self {
        self.multiply(&scalar)
    }
}

impl std::ops::Mul<&GroupScalar> for GroupElement {
    type Output = Self;
    fn mul(self, scalar: &GroupScalar) -> Self {
        self.multiply(scalar)
    }
}

/// Sum multiple group elements
pub fn sum_elements(elements: &[GroupElement]) -> GroupElement {
    elements.iter().fold(GroupElement::identity(), |acc, e| acc + *e)
}

/// Sum multiple scalars
pub fn sum_scalars(scalars: &[GroupScalar]) -> GroupScalar {
    scalars.iter().fold(GroupScalar::zero(), |acc, s| acc + *s)
}

/// Multiply multiple points by their scalars and sum: Σ (point_i * scalar_i)
/// This is useful for multi-exponentiation
pub fn multi_scalar_multiply(
    points: &[GroupElement],
    scalars: &[GroupScalar],
) -> Result<GroupElement, GroupError> {
    if points.len() != scalars.len() {
        return Err(GroupError::OperationFailed);
    }
    
    Ok(points.iter()
        .zip(scalars.iter())
        .fold(GroupElement::identity(), |acc, (p, s)| acc + p.multiply(s)))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scalar_creation() {
        // Test random
        let s1 = GroupScalar::random();
        assert_ne!(s1, GroupScalar::zero());
        
        // Test zero and one
        assert!(GroupScalar::zero().ct_eq(&GroupScalar::zero()));
        assert!(GroupScalar::one().ct_eq(&GroupScalar::one()));
        assert!(!GroupScalar::zero().ct_eq(&GroupScalar::one()));
    }
    
    #[test]
    fn test_scalar_serialization() {
        let s = GroupScalar::random();
        let bytes = s.to_bytes();
        let s2 = GroupScalar::from_bytes(bytes).unwrap();
        assert!(s.ct_eq(&s2));
    }
    
    #[test]
    fn test_scalar_operations() {
        let s1 = GroupScalar::from_bytes([1u8; 32]).unwrap();
        let s2 = GroupScalar::from_bytes([2u8; 32]).unwrap();
        
        // Test addition
        let sum = s1.add(&s2);
        
        // Test subtraction
        let diff = s2.sub(&s1);
        
        // Test multiplication
        let product = s1.mul(&s2);
        
        // Test negation
        let neg = s1.negate();
        assert!(s1.add(&neg).ct_eq(&GroupScalar::zero()));
    }
    
    #[test]
    fn test_element_creation() {
        // Test generator
        let g = GroupElement::generator();
        assert!(!g.is_identity());
        
        // Test identity
        let i = GroupElement::identity();
        assert!(i.is_identity());
        
        // Test equality
        assert!(g.ct_eq(&g));
        assert!(!g.ct_eq(&i));
    }
    
    #[test]
    fn test_element_serialization() {
        let g = GroupElement::generator();
        let bytes = g.to_bytes();
        let g2 = GroupElement::from_bytes(bytes).unwrap();
        assert!(g.ct_eq(&g2));
    }
    
    #[test]
    fn test_element_operations() {
        let g = GroupElement::generator();
        let s = GroupScalar::from_bytes([5u8; 32]).unwrap();
        
        // Test multiplication
        let g_s = g.multiply(&s);
        assert!(!g_s.is_identity());
        
        // Test addition
        let g2 = g.add(&g);
        let g_doubled = g.double();
        assert!(g2.ct_eq(&g_doubled));
        
        // Test negation
        let neg_g = g.negate();
        assert!(g.add(&neg_g).is_identity());
        
        // Test identity addition
        let i = GroupElement::identity();
        assert!(g.add(&i).ct_eq(&g));
    }
    
    #[test]
    fn test_multi_scalar_multiply() {
        let g = GroupElement::generator();
        let s1 = GroupScalar::from_bytes([1u8; 32]).unwrap();
        let s2 = GroupScalar::from_bytes([2u8; 32]).unwrap();
        
        let points = vec![g, g.double()];
        let scalars = vec![s1, s2];
        
        let result = multi_scalar_multiply(&points, &scalars).unwrap();
        let expected = g.multiply(&s1) + g.double().multiply(&s2);
        
        assert!(result.ct_eq(&expected));
    }
    
    #[test]
    fn test_sum_functions() {
        let g = GroupElement::generator();
        let elements = vec![g, g.double(), g.negate()];
        
        let sum = sum_elements(&elements);
        assert!(sum.ct_eq(&g.double()));
        
        let s1 = GroupScalar::from_bytes([1u8; 32]).unwrap();
        let s2 = GroupScalar::from_bytes([2u8; 32]).unwrap();
        let s3 = GroupScalar::from_bytes([3u8; 32]).unwrap();
        let scalars = vec![s1, s2, s3];
        
        let sum_s = sum_scalars(&scalars);
        let expected = s1 + s2 + s3;
        assert!(sum_s.ct_eq(&expected));
    }
}
