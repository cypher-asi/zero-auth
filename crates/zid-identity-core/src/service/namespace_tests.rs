//! Tests for namespace operations.

use super::*;
use crate::traits::mocks::MockEventPublisher;
use crate::types::{CreateIdentityRequest, MachineKey};
use std::sync::Arc;
use uuid::Uuid;
use zid_crypto::{
    canonicalize_identity_creation_message, derive_identity_signing_keypair, sign_message,
    MachineKeyCapabilities, NeuralKey,
};
use zid_policy::PolicyEngineImpl;
use zid_storage::RocksDbStorage;

// Helper to create a test service
fn create_test_service() -> IdentityCoreService<
    PolicyEngineImpl<RocksDbStorage>,
    MockEventPublisher,
    RocksDbStorage,
> {
    let storage = Arc::new(RocksDbStorage::open_test().unwrap());
    let policy = Arc::new(PolicyEngineImpl::new(Arc::clone(&storage)));
    let events = Arc::new(MockEventPublisher);
    IdentityCoreService::new(policy, events, storage)
}

// Helper to create a test identity
async fn create_test_identity(
    service: &IdentityCoreService<PolicyEngineImpl<RocksDbStorage>, MockEventPublisher, RocksDbStorage>,
) -> Uuid {
    let neural_key = NeuralKey::generate().unwrap();
    let identity_id = Uuid::new_v4();
    let (identity_signing_public_key, identity_keypair) =
        derive_identity_signing_keypair(&neural_key, &identity_id).unwrap();

    let machine_id = Uuid::new_v4();
    let machine_key = MachineKey {
        machine_id,
        identity_id,
        namespace_id: identity_id,
        signing_public_key: [1u8; 32],
        encryption_public_key: [2u8; 32],
        capabilities: MachineKeyCapabilities::FULL_DEVICE,
        epoch: 0,
        created_at: current_timestamp(),
        expires_at: None,
        last_used_at: None,
        device_name: "test-device".to_string(),
        device_platform: "test".to_string(),
        revoked: false,
        revoked_at: None,
        key_scheme: Default::default(),
        pq_signing_public_key: None,
        pq_encryption_public_key: None,
    };

    let message = canonicalize_identity_creation_message(
        &identity_id,
        &identity_signing_public_key,
        &machine_id,
        &machine_key.signing_public_key,
        &machine_key.encryption_public_key,
        machine_key.created_at,
    );

    let signature = sign_message(&identity_keypair, &message);

    let request = CreateIdentityRequest {
        identity_id,
        identity_signing_public_key,
        machine_key,
        authorization_signature: signature.to_vec(),
        namespace_name: Some("test-namespace".to_string()),
        created_at: current_timestamp(),
    };

    service.create_identity_internal(request).await.unwrap();
    identity_id
}

// ========================================================================
// Namespace CRUD Tests
// ========================================================================

#[tokio::test]
async fn test_create_namespace_success() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    let namespace = service
        .create_namespace_internal(namespace_id, "Test Namespace".to_string(), owner_id)
        .await
        .unwrap();

    assert_eq!(namespace.namespace_id, namespace_id);
    assert_eq!(namespace.name, "Test Namespace");
    assert_eq!(namespace.owner_identity_id, owner_id);
    assert!(namespace.active);
}

#[tokio::test]
async fn test_create_namespace_duplicate_fails() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Namespace 1".to_string(), owner_id)
        .await
        .unwrap();

    let result = service
        .create_namespace_internal(namespace_id, "Namespace 2".to_string(), owner_id)
        .await;

    assert!(matches!(
        result,
        Err(IdentityCoreError::NamespaceAlreadyExists(_))
    ));
}

#[tokio::test]
async fn test_list_namespaces_returns_all_memberships() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;

    // The personal namespace should be queryable by ID
    let personal_ns = service.get_namespace_internal(owner_id).await.unwrap();
    assert_eq!(personal_ns.namespace_id, owner_id);

    // Create two additional namespaces
    let ns1 = Uuid::new_v4();
    let ns2 = Uuid::new_v4();
    let created_ns1 = service
        .create_namespace_internal(ns1, "NS1".to_string(), owner_id)
        .await
        .unwrap();
    assert_eq!(created_ns1.namespace_id, ns1);

    let created_ns2 = service
        .create_namespace_internal(ns2, "NS2".to_string(), owner_id)
        .await
        .unwrap();
    assert_eq!(created_ns2.namespace_id, ns2);

    // Verify we can get each namespace individually
    let fetched_ns1 = service.get_namespace_internal(ns1).await.unwrap();
    assert_eq!(fetched_ns1.name, "NS1");

    // Directly verify the index was written by checking with exact key
    let index_key = (owner_id, ns1);
    let index_exists: Option<()> = service
        .storage
        .get(zid_storage::CF_NAMESPACES_BY_IDENTITY, &index_key)
        .await
        .unwrap();
    assert!(
        index_exists.is_some(),
        "Index entry for ns1 should exist"
    );

    let namespaces = service.list_namespaces_internal(owner_id).await.unwrap();

    // Should have personal namespace + 2 created
    assert_eq!(namespaces.len(), 3);
}

#[tokio::test]
async fn test_update_namespace_as_owner_success() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Old Name".to_string(), owner_id)
        .await
        .unwrap();

    let updated = service
        .update_namespace_internal(namespace_id, "New Name".to_string(), owner_id)
        .await
        .unwrap();

    assert_eq!(updated.name, "New Name");
}

#[tokio::test]
async fn test_update_namespace_as_non_owner_fails() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let member_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    // Add member as Admin
    service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Admin, owner_id)
        .await
        .unwrap();

    // Admin tries to update namespace
    let result = service
        .update_namespace_internal(namespace_id, "New Name".to_string(), member_id)
        .await;

    assert!(matches!(
        result,
        Err(IdentityCoreError::InsufficientPermissions { .. })
    ));
}

#[tokio::test]
async fn test_deactivate_namespace_success() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .deactivate_namespace_internal(namespace_id, owner_id)
        .await
        .unwrap();

    let namespace = service.get_namespace_internal(namespace_id).await.unwrap();
    assert!(!namespace.active);
}

#[tokio::test]
async fn test_reactivate_namespace_success() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();
    service
        .deactivate_namespace_internal(namespace_id, owner_id)
        .await
        .unwrap();

    service
        .reactivate_namespace_internal(namespace_id, owner_id)
        .await
        .unwrap();

    let namespace = service.get_namespace_internal(namespace_id).await.unwrap();
    assert!(namespace.active);
}

#[tokio::test]
async fn test_delete_namespace_empty_success() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .delete_namespace_internal(namespace_id, owner_id)
        .await
        .unwrap();

    let result = service.get_namespace_internal(namespace_id).await;
    assert!(matches!(
        result,
        Err(IdentityCoreError::NamespaceNotFound(_))
    ));
}

#[tokio::test]
async fn test_delete_namespace_with_members_fails() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let member_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
        .await
        .unwrap();

    let result = service
        .delete_namespace_internal(namespace_id, owner_id)
        .await;

    assert!(matches!(
        result,
        Err(IdentityCoreError::NamespaceHasMembers(_))
    ));
}

// ========================================================================
// Membership Management Tests
// ========================================================================

#[tokio::test]
async fn test_add_member_as_owner_success() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let member_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    let membership = service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
        .await
        .unwrap();

    assert_eq!(membership.identity_id, member_id);
    assert_eq!(membership.namespace_id, namespace_id);
    assert_eq!(membership.role, NamespaceRole::Member);
}

#[tokio::test]
async fn test_add_member_as_admin_success() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let admin_id = create_test_identity(&service).await;
    let member_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    // Add admin
    service
        .add_namespace_member_internal(namespace_id, admin_id, NamespaceRole::Admin, owner_id)
        .await
        .unwrap();

    // Admin adds member
    let membership = service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, admin_id)
        .await
        .unwrap();

    assert_eq!(membership.role, NamespaceRole::Member);
}

#[tokio::test]
async fn test_add_member_as_member_fails() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let member1_id = create_test_identity(&service).await;
    let member2_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .add_namespace_member_internal(namespace_id, member1_id, NamespaceRole::Member, owner_id)
        .await
        .unwrap();

    // Member tries to add another member
    let result = service
        .add_namespace_member_internal(namespace_id, member2_id, NamespaceRole::Member, member1_id)
        .await;

    assert!(matches!(
        result,
        Err(IdentityCoreError::InsufficientPermissions { .. })
    ));
}

#[tokio::test]
async fn test_add_member_already_exists_fails() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let member_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
        .await
        .unwrap();

    let result = service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Admin, owner_id)
        .await;

    assert!(matches!(
        result,
        Err(IdentityCoreError::MemberAlreadyExists { .. })
    ));
}

#[tokio::test]
async fn test_update_member_role_success() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let member_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
        .await
        .unwrap();

    let updated = service
        .update_namespace_member_internal(namespace_id, member_id, NamespaceRole::Admin, owner_id)
        .await
        .unwrap();

    assert_eq!(updated.role, NamespaceRole::Admin);
}

#[tokio::test]
async fn test_update_member_cannot_demote_owner() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    let result = service
        .update_namespace_member_internal(namespace_id, owner_id, NamespaceRole::Admin, owner_id)
        .await;

    assert!(matches!(result, Err(IdentityCoreError::CannotRemoveOwner)));
}

#[tokio::test]
async fn test_remove_member_success() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let member_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
        .await
        .unwrap();

    service
        .remove_namespace_member_internal(namespace_id, member_id, owner_id)
        .await
        .unwrap();

    let membership = service
        .get_namespace_membership_internal(member_id, namespace_id)
        .await
        .unwrap();
    assert!(membership.is_none());
}

#[tokio::test]
async fn test_remove_owner_fails() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    let result = service
        .remove_namespace_member_internal(namespace_id, owner_id, owner_id)
        .await;

    assert!(matches!(result, Err(IdentityCoreError::CannotRemoveOwner)));
}

#[tokio::test]
async fn test_admin_cannot_remove_admin() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let admin1_id = create_test_identity(&service).await;
    let admin2_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .add_namespace_member_internal(namespace_id, admin1_id, NamespaceRole::Admin, owner_id)
        .await
        .unwrap();
    service
        .add_namespace_member_internal(namespace_id, admin2_id, NamespaceRole::Admin, owner_id)
        .await
        .unwrap();

    let result = service
        .remove_namespace_member_internal(namespace_id, admin2_id, admin1_id)
        .await;

    assert!(matches!(
        result,
        Err(IdentityCoreError::InsufficientPermissions { .. })
    ));
}

#[tokio::test]
async fn test_member_can_self_remove() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let member_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
        .await
        .unwrap();

    // Member removes themselves
    service
        .remove_namespace_member_internal(namespace_id, member_id, member_id)
        .await
        .unwrap();

    let membership = service
        .get_namespace_membership_internal(member_id, namespace_id)
        .await
        .unwrap();
    assert!(membership.is_none());
}

#[tokio::test]
async fn test_operations_on_inactive_namespace_fail() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let member_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();
    service
        .deactivate_namespace_internal(namespace_id, owner_id)
        .await
        .unwrap();

    // Try to add member to inactive namespace
    let result = service
        .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
        .await;

    assert!(matches!(
        result,
        Err(IdentityCoreError::NamespaceNotActive(_))
    ));
}

#[tokio::test]
async fn test_admin_cannot_add_admin() {
    let service = create_test_service();
    let owner_id = create_test_identity(&service).await;
    let admin_id = create_test_identity(&service).await;
    let new_admin_id = create_test_identity(&service).await;

    let namespace_id = Uuid::new_v4();
    service
        .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
        .await
        .unwrap();

    service
        .add_namespace_member_internal(namespace_id, admin_id, NamespaceRole::Admin, owner_id)
        .await
        .unwrap();

    // Admin tries to add another admin
    let result = service
        .add_namespace_member_internal(namespace_id, new_admin_id, NamespaceRole::Admin, admin_id)
        .await;

    assert!(matches!(
        result,
        Err(IdentityCoreError::InsufficientPermissions { .. })
    ));
}
