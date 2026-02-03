//! Namespace operations: create, get, update, delete, membership management.

use crate::{errors::*, traits::EventPublisher, types::*};
use tracing::info;
use uuid::Uuid;
use zid_policy::PolicyEngine;
use zid_storage::{
    traits::BatchExt, Storage, CF_IDENTITY_NAMESPACE_MEMBERSHIPS, CF_NAMESPACES,
    CF_NAMESPACES_BY_IDENTITY,
};

use super::IdentityCoreService;

// ============================================================================
// Authorization Helpers
// ============================================================================

/// Check if a role can manage members (add/update/remove)
fn can_manage_members(role: NamespaceRole) -> bool {
    matches!(role, NamespaceRole::Owner | NamespaceRole::Admin)
}

/// Check if a role can modify namespace settings
fn can_modify_namespace(role: NamespaceRole) -> bool {
    role == NamespaceRole::Owner
}

impl<P, E, S> IdentityCoreService<P, E, S>
where
    P: PolicyEngine + 'static,
    E: EventPublisher + 'static,
    S: Storage + 'static,
{
    // ========================================================================
    // Namespace CRUD Operations
    // ========================================================================

    /// Create a new namespace with owner membership
    pub(crate) async fn create_namespace_internal(
        &self,
        namespace_id: Uuid,
        name: String,
        owner_identity_id: Uuid,
    ) -> Result<Namespace> {
        // Check if namespace already exists
        if self
            .storage
            .get::<Uuid, Namespace>(CF_NAMESPACES, &namespace_id)
            .await?
            .is_some()
        {
            return Err(IdentityCoreError::NamespaceAlreadyExists(namespace_id));
        }

        // Verify owner identity exists
        self.get_identity_internal(owner_identity_id).await?;

        let now = current_timestamp();

        let namespace = Namespace {
            namespace_id,
            name,
            created_at: now,
            owner_identity_id,
            active: true,
        };

        // Create owner membership
        let membership = IdentityNamespaceMembership {
            identity_id: owner_identity_id,
            namespace_id,
            role: NamespaceRole::Owner,
            joined_at: now,
        };

        // Persist namespace, membership, and index in a batch
        let mut batch = self.storage.batch();

        batch.put(CF_NAMESPACES, &namespace_id, &namespace)?;

        let membership_key = (owner_identity_id, namespace_id);
        batch.put(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key, &membership)?;

        // Add to namespaces-by-identity index
        let index_key = (owner_identity_id, namespace_id);
        batch.put(CF_NAMESPACES_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;

        info!(
            "Namespace created: {} by owner {}",
            namespace_id, owner_identity_id
        );

        Ok(namespace)
    }

    /// Get a namespace by ID
    pub(crate) async fn get_namespace_internal(&self, namespace_id: Uuid) -> Result<Namespace> {
        self.storage
            .get(CF_NAMESPACES, &namespace_id)
            .await?
            .ok_or(IdentityCoreError::NamespaceNotFound(namespace_id))
    }

    /// Get namespace membership for an identity
    pub(crate) async fn get_namespace_membership_internal(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
    ) -> Result<Option<IdentityNamespaceMembership>> {
        let key = (identity_id, namespace_id);
        Ok(self
            .storage
            .get(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &key)
            .await?)
    }

    /// List all namespaces for an identity
    pub(crate) async fn list_namespaces_internal(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<Namespace>> {
        // Query the namespaces-by-identity index
        let index_entries: Vec<(Vec<u8>, ())> = self
            .storage
            .get_by_prefix(CF_NAMESPACES_BY_IDENTITY, &identity_id)
            .await?;

        let mut namespaces = Vec::new();

        for (key_bytes, _) in index_entries {
            // Key format with bincode serialization:
            // - 8 bytes: length prefix for first Uuid (always 16)
            // - 16 bytes: identity_id
            // - 8 bytes: length prefix for second Uuid (always 16)
            // - 16 bytes: namespace_id
            // Total: 48 bytes
            if key_bytes.len() >= 48 {
                let namespace_id_bytes = &key_bytes[32..48];
                let namespace_id = Uuid::from_slice(namespace_id_bytes).map_err(|e| {
                    IdentityCoreError::Storage(zid_storage::StorageError::Deserialization(
                        e.to_string(),
                    ))
                })?;

                if let Some(namespace) = self.storage.get(CF_NAMESPACES, &namespace_id).await? {
                    namespaces.push(namespace);
                }
            }
        }

        Ok(namespaces)
    }

    /// Update a namespace (name only)
    pub(crate) async fn update_namespace_internal(
        &self,
        namespace_id: Uuid,
        name: String,
        requester_id: Uuid,
    ) -> Result<Namespace> {
        let mut namespace = self.get_namespace_internal(namespace_id).await?;

        // Check authorization - only owner can modify
        let membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_modify_namespace(membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: membership.role,
                action: "update namespace".to_string(),
            });
        }

        namespace.name = name;

        self.storage
            .put(CF_NAMESPACES, &namespace_id, &namespace)
            .await?;

        info!("Namespace {} updated by {}", namespace_id, requester_id);

        Ok(namespace)
    }

    /// Deactivate a namespace
    pub(crate) async fn deactivate_namespace_internal(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()> {
        let mut namespace = self.get_namespace_internal(namespace_id).await?;

        // Check authorization - only owner can deactivate
        let membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_modify_namespace(membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: membership.role,
                action: "deactivate namespace".to_string(),
            });
        }

        namespace.active = false;

        self.storage
            .put(CF_NAMESPACES, &namespace_id, &namespace)
            .await?;

        info!("Namespace {} deactivated by {}", namespace_id, requester_id);

        Ok(())
    }

    /// Reactivate a namespace
    pub(crate) async fn reactivate_namespace_internal(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()> {
        let mut namespace = self.get_namespace_internal(namespace_id).await?;

        // Check authorization - only owner can reactivate
        let membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_modify_namespace(membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: membership.role,
                action: "reactivate namespace".to_string(),
            });
        }

        namespace.active = true;

        self.storage
            .put(CF_NAMESPACES, &namespace_id, &namespace)
            .await?;

        info!("Namespace {} reactivated by {}", namespace_id, requester_id);

        Ok(())
    }

    /// Delete a namespace (must have no other members)
    pub(crate) async fn delete_namespace_internal(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()> {
        let namespace = self.get_namespace_internal(namespace_id).await?;

        // Check authorization - only owner can delete
        let membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_modify_namespace(membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: membership.role,
                action: "delete namespace".to_string(),
            });
        }

        // Check that namespace has no other members
        let members = self
            .list_namespace_members_internal(namespace_id, requester_id)
            .await?;
        if members.len() > 1 {
            return Err(IdentityCoreError::NamespaceHasMembers(namespace_id));
        }

        // Delete namespace, membership, and index in a batch
        let mut batch = self.storage.batch();

        batch.delete(CF_NAMESPACES, &namespace_id)?;

        let membership_key = (namespace.owner_identity_id, namespace_id);
        batch.delete(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key)?;

        let index_key = (namespace.owner_identity_id, namespace_id);
        batch.delete(CF_NAMESPACES_BY_IDENTITY, &index_key)?;

        batch.commit().await?;

        info!("Namespace {} deleted by {}", namespace_id, requester_id);

        Ok(())
    }

    // ========================================================================
    // Membership Management
    // ========================================================================

    /// List all members of a namespace
    pub(crate) async fn list_namespace_members_internal(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<Vec<IdentityNamespaceMembership>> {
        // Verify namespace exists
        let namespace = self.get_namespace_internal(namespace_id).await?;

        // Check that namespace is active
        if !namespace.active {
            return Err(IdentityCoreError::NamespaceNotActive(namespace_id));
        }

        // Check requester is a member
        self.get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        // Get all memberships for this namespace
        // We need to scan by namespace_id, but our key is (identity_id, namespace_id)
        // This requires scanning all memberships - in production, consider adding
        // a reverse index (namespace_id, identity_id) -> ()
        // For now, we'll use a workaround by iterating through known patterns
        
        // A more efficient approach: iterate through namespaces-by-identity in reverse
        // For now, we'll iterate all memberships and filter
        let all_memberships: Vec<(Vec<u8>, IdentityNamespaceMembership)> = self
            .storage
            .scan_all(CF_IDENTITY_NAMESPACE_MEMBERSHIPS)
            .await?;

        let members: Vec<IdentityNamespaceMembership> = all_memberships
            .into_iter()
            .map(|(_, m)| m)
            .filter(|m| m.namespace_id == namespace_id)
            .collect();

        Ok(members)
    }

    /// Add a member to a namespace
    pub(crate) async fn add_namespace_member_internal(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        role: NamespaceRole,
        requester_id: Uuid,
    ) -> Result<IdentityNamespaceMembership> {
        // Verify namespace exists and is active
        let namespace = self.get_namespace_internal(namespace_id).await?;
        if !namespace.active {
            return Err(IdentityCoreError::NamespaceNotActive(namespace_id));
        }

        // Verify target identity exists
        self.get_identity_internal(identity_id).await?;

        // Check authorization - owner/admin can add members
        let requester_membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_manage_members(requester_membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: "add members".to_string(),
            });
        }

        // Admins can only add Members, not other Admins or Owners
        if requester_membership.role == NamespaceRole::Admin && role != NamespaceRole::Member {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: format!("add {:?} role", role),
            });
        }

        // Cannot add Owner role (there can only be one owner)
        if role == NamespaceRole::Owner {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: "add Owner role".to_string(),
            });
        }

        // Check if member already exists
        if self
            .get_namespace_membership_internal(identity_id, namespace_id)
            .await?
            .is_some()
        {
            return Err(IdentityCoreError::MemberAlreadyExists {
                identity_id,
                namespace_id,
            });
        }

        let now = current_timestamp();
        let membership = IdentityNamespaceMembership {
            identity_id,
            namespace_id,
            role,
            joined_at: now,
        };

        // Persist membership and index
        let mut batch = self.storage.batch();

        let membership_key = (identity_id, namespace_id);
        batch.put(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key, &membership)?;

        let index_key = (identity_id, namespace_id);
        batch.put(CF_NAMESPACES_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;

        info!(
            "Member {} added to namespace {} with role {:?} by {}",
            identity_id, namespace_id, role, requester_id
        );

        Ok(membership)
    }

    /// Update a member's role in a namespace
    pub(crate) async fn update_namespace_member_internal(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        new_role: NamespaceRole,
        requester_id: Uuid,
    ) -> Result<IdentityNamespaceMembership> {
        // Verify namespace exists and is active
        let namespace = self.get_namespace_internal(namespace_id).await?;
        if !namespace.active {
            return Err(IdentityCoreError::NamespaceNotActive(namespace_id));
        }

        // Get target membership
        let mut membership = self
            .get_namespace_membership_internal(identity_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::MemberNotFound {
                identity_id,
                namespace_id,
            })?;

        // Check authorization
        let requester_membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_manage_members(requester_membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: "update member role".to_string(),
            });
        }

        // Cannot change Owner's role
        if membership.role == NamespaceRole::Owner {
            return Err(IdentityCoreError::CannotRemoveOwner);
        }

        // Cannot promote to Owner
        if new_role == NamespaceRole::Owner {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: "promote to Owner".to_string(),
            });
        }

        // Admins can only manage Members (not other Admins)
        if requester_membership.role == NamespaceRole::Admin {
            if membership.role == NamespaceRole::Admin {
                return Err(IdentityCoreError::InsufficientPermissions {
                    role: requester_membership.role,
                    action: "modify Admin role".to_string(),
                });
            }
            if new_role == NamespaceRole::Admin {
                return Err(IdentityCoreError::InsufficientPermissions {
                    role: requester_membership.role,
                    action: "promote to Admin".to_string(),
                });
            }
        }

        membership.role = new_role;

        let membership_key = (identity_id, namespace_id);
        self.storage
            .put(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key, &membership)
            .await?;

        info!(
            "Member {} role updated to {:?} in namespace {} by {}",
            identity_id, new_role, namespace_id, requester_id
        );

        Ok(membership)
    }

    /// Remove a member from a namespace
    pub(crate) async fn remove_namespace_member_internal(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()> {
        // Verify namespace exists and is active
        let namespace = self.get_namespace_internal(namespace_id).await?;
        if !namespace.active {
            return Err(IdentityCoreError::NamespaceNotActive(namespace_id));
        }

        // Get target membership
        let membership = self
            .get_namespace_membership_internal(identity_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::MemberNotFound {
                identity_id,
                namespace_id,
            })?;

        // Cannot remove owner
        if membership.role == NamespaceRole::Owner {
            return Err(IdentityCoreError::CannotRemoveOwner);
        }

        // Check authorization
        let requester_membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        // Allow self-removal
        if identity_id != requester_id {
            if !can_manage_members(requester_membership.role) {
                return Err(IdentityCoreError::InsufficientPermissions {
                    role: requester_membership.role,
                    action: "remove members".to_string(),
                });
            }

            // Admins cannot remove other Admins
            if requester_membership.role == NamespaceRole::Admin
                && membership.role == NamespaceRole::Admin
            {
                return Err(IdentityCoreError::InsufficientPermissions {
                    role: requester_membership.role,
                    action: "remove Admin".to_string(),
                });
            }
        }

        // Delete membership and index
        let mut batch = self.storage.batch();

        let membership_key = (identity_id, namespace_id);
        batch.delete(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key)?;

        let index_key = (identity_id, namespace_id);
        batch.delete(CF_NAMESPACES_BY_IDENTITY, &index_key)?;

        batch.commit().await?;

        info!(
            "Member {} removed from namespace {} by {}",
            identity_id, namespace_id, requester_id
        );

        Ok(())
    }
}
