//! Minimal mask-based admission core for layered policy updates.
//!
//! This intentionally contains no agent, YAML, DSL, or business-role concepts.
//! Callers resolve principals, relationships, and scope IDs before invoking it.

pub const AFFECT_SELF: u64 = 1 << 0;
pub const AFFECT_CHILD: u64 = 1 << 1;
pub const AFFECT_SUBTREE: u64 = 1 << 2;

pub const CAP_ADD_RESTRICTION: u64 = 1 << 0;
pub const CAP_ADD_LABEL: u64 = 1 << 1;
pub const CAP_REQUIRE_GATE: u64 = 1 << 2;
pub const CAP_NARROW_SCOPE: u64 = 1 << 3;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrincipalState {
    pub parent: u32,
    pub subtree_root: u32,
    pub scope_id: u32,
    pub labels: u64,
    pub update_cap_mask: u64,
    pub affect_scope_mask: u64,
    pub effective_restrict: u64,
    pub required_gates: u64,
    pub allowed_label_mask: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyRequest {
    pub required_cap_mask: u64,
    pub add_restrict_mask: u64,
    pub add_label_mask: u64,
    pub require_gate_mask: u64,
    pub new_scope_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitError {
    ScopeAuthority,
    UpdateCapability,
    LabelAuthority,
    ScopeWiden,
}

fn implied_cap_mask(req: PolicyRequest) -> u64 {
    let mut mask = req.required_cap_mask;
    if req.add_restrict_mask != 0 {
        mask |= CAP_ADD_RESTRICTION;
    }
    if req.add_label_mask != 0 {
        mask |= CAP_ADD_LABEL;
    }
    if req.require_gate_mask != 0 {
        mask |= CAP_REQUIRE_GATE;
    }
    if req.new_scope_id != 0 {
        mask |= CAP_NARROW_SCOPE;
    }
    mask
}

pub fn admit_delta(
    src: &PrincipalState,
    dst: &mut PrincipalState,
    relation_mask: u64,
    req: PolicyRequest,
    scope_subset: impl Fn(u32, u32) -> bool,
) -> Result<(), AdmitError> {
    if relation_mask & src.affect_scope_mask == 0 {
        return Err(AdmitError::ScopeAuthority);
    }
    if implied_cap_mask(req) & !src.update_cap_mask != 0 {
        return Err(AdmitError::UpdateCapability);
    }
    if req.add_label_mask & !src.allowed_label_mask != 0 {
        return Err(AdmitError::LabelAuthority);
    }
    if req.new_scope_id != 0 && !scope_subset(req.new_scope_id, dst.scope_id) {
        return Err(AdmitError::ScopeWiden);
    }

    dst.effective_restrict |= req.add_restrict_mask;
    dst.labels |= req.add_label_mask;
    dst.required_gates |= req.require_gate_mask;
    if req.new_scope_id != 0 {
        dst.scope_id = req.new_scope_id;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_subset(new_scope: u32, old_scope: u32) -> bool {
        new_scope >= old_scope
    }

    #[test]
    fn admits_monotonic_child_delta() {
        let src = PrincipalState {
            update_cap_mask: CAP_ADD_RESTRICTION | CAP_ADD_LABEL | CAP_NARROW_SCOPE,
            affect_scope_mask: AFFECT_CHILD,
            allowed_label_mask: 0b0100,
            ..PrincipalState::default()
        };
        let mut dst = PrincipalState {
            scope_id: 1,
            labels: 0b0001,
            effective_restrict: 0b0010,
            ..PrincipalState::default()
        };
        admit_delta(
            &src,
            &mut dst,
            AFFECT_CHILD,
            PolicyRequest {
                required_cap_mask: CAP_ADD_RESTRICTION | CAP_ADD_LABEL | CAP_NARROW_SCOPE,
                add_restrict_mask: 0b1000,
                add_label_mask: 0b0100,
                new_scope_id: 2,
                ..PolicyRequest::default()
            },
            scope_subset,
        )
        .unwrap();
        assert_eq!(dst.effective_restrict, 0b1010);
        assert_eq!(dst.labels, 0b0101);
        assert_eq!(dst.scope_id, 2);
    }

    #[test]
    fn rejects_non_monotonic_authority_gaps() {
        let src = PrincipalState {
            update_cap_mask: CAP_ADD_RESTRICTION,
            affect_scope_mask: AFFECT_SELF,
            allowed_label_mask: 0b0001,
            ..PrincipalState::default()
        };
        let base = PrincipalState {
            scope_id: 4,
            labels: 0b0010,
            effective_restrict: 0b0100,
            ..PrincipalState::default()
        };

        let mut dst = base;
        assert_eq!(
            admit_delta(
                &src,
                &mut dst,
                AFFECT_CHILD,
                PolicyRequest::default(),
                scope_subset
            ),
            Err(AdmitError::ScopeAuthority)
        );
        assert_eq!(dst, base);

        let mut dst = base;
        assert_eq!(
            admit_delta(
                &src,
                &mut dst,
                AFFECT_SELF,
                PolicyRequest {
                    required_cap_mask: CAP_ADD_LABEL,
                    ..PolicyRequest::default()
                },
                scope_subset
            ),
            Err(AdmitError::UpdateCapability)
        );

        let mut dst = base;
        let src_with_label_cap = PrincipalState {
            update_cap_mask: CAP_ADD_RESTRICTION | CAP_ADD_LABEL,
            ..src
        };
        assert_eq!(
            admit_delta(
                &src,
                &mut dst,
                AFFECT_SELF,
                PolicyRequest {
                    add_label_mask: 0b0001,
                    ..PolicyRequest::default()
                },
                scope_subset
            ),
            Err(AdmitError::UpdateCapability)
        );

        let mut dst = base;
        assert_eq!(
            admit_delta(
                &src_with_label_cap,
                &mut dst,
                AFFECT_SELF,
                PolicyRequest {
                    add_label_mask: 0b1000,
                    ..PolicyRequest::default()
                },
                scope_subset
            ),
            Err(AdmitError::LabelAuthority)
        );

        let mut dst = base;
        let src_with_scope_cap = PrincipalState {
            update_cap_mask: CAP_ADD_RESTRICTION | CAP_NARROW_SCOPE,
            ..src
        };
        assert_eq!(
            admit_delta(
                &src_with_scope_cap,
                &mut dst,
                AFFECT_SELF,
                PolicyRequest {
                    new_scope_id: 3,
                    ..PolicyRequest::default()
                },
                scope_subset
            ),
            Err(AdmitError::ScopeWiden)
        );
    }
}
