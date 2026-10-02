//! Minimal mask-based admission core for policy deltas.
//!
//! This intentionally contains no agent, YAML, DSL, or business-role concepts.
//! Callers resolve target IDs, parent links, and scope IDs before invoking it.

pub const TARGET_SELF: u64 = 1 << 0;
pub const TARGET_CHILD: u64 = 1 << 1;

pub const AUTH_ADD_RESTRICTION: u64 = 1 << 0;
pub const AUTH_ADD_LABEL: u64 = 1 << 1;
pub const AUTH_REQUIRE_GATE: u64 = 1 << 2;
pub const AUTH_NARROW_SCOPE: u64 = 1 << 3;
pub const AUTH_BIND_RULE: u64 = 1 << 4;
pub const AUTH_DECLASSIFY: u64 = 1 << 5;
pub const AUTH_DELEGATE: u64 = 1 << 6;

pub const STAT_ACCEPT: u32 = 0;
pub const STAT_REJECT: u32 = 1;
pub const STAT_DRAIN: u32 = 2;
pub const STAT_DROP: u32 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapState {
    pub parent: u32,
    pub scope_id: u32,
    pub labels: u64,
    pub authority_mask: u64,
    pub target_mask: u64,
    pub restrict_mask: u64,
    pub gate_mask: u64,
    pub label_mask: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeltaRequest {
    pub caller_pid: i32,
    pub target_id: u32,
    pub new_scope_id: u32,
    pub required_mask: u64,
    pub add_restrict_mask: u64,
    pub add_label_mask: u64,
    pub add_gate_mask: u64,
}

unsafe impl aya::Pod for CapState {}
unsafe impl aya::Pod for DeltaRequest {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitError {
    TargetAuthority,
    UpdateAuthority,
    LabelAuthority,
    ScopeWiden,
}

fn required_mask(req: DeltaRequest) -> u64 {
    let mut mask = req.required_mask;
    if req.add_restrict_mask != 0 {
        mask |= AUTH_ADD_RESTRICTION;
    }
    if req.add_label_mask != 0 {
        mask |= AUTH_ADD_LABEL;
    }
    if req.add_gate_mask != 0 {
        mask |= AUTH_REQUIRE_GATE;
    }
    if req.new_scope_id != 0 {
        mask |= AUTH_NARROW_SCOPE;
    }
    mask
}

pub fn admit_delta(
    src: &CapState,
    dst: &mut CapState,
    target_mask: u64,
    req: DeltaRequest,
    scope_subset: impl Fn(u32, u32) -> bool,
) -> Result<(), AdmitError> {
    if target_mask & src.target_mask == 0 {
        return Err(AdmitError::TargetAuthority);
    }
    if required_mask(req) & !src.authority_mask != 0 {
        return Err(AdmitError::UpdateAuthority);
    }
    if req.add_label_mask & !src.label_mask != 0 {
        return Err(AdmitError::LabelAuthority);
    }
    if req.new_scope_id != 0 && !scope_subset(req.new_scope_id, dst.scope_id) {
        return Err(AdmitError::ScopeWiden);
    }

    dst.restrict_mask |= req.add_restrict_mask;
    dst.labels |= req.add_label_mask;
    dst.gate_mask |= req.add_gate_mask;
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
        let src = CapState {
            authority_mask: AUTH_ADD_RESTRICTION
                | AUTH_ADD_LABEL
                | AUTH_NARROW_SCOPE
                | AUTH_BIND_RULE,
            target_mask: TARGET_CHILD,
            label_mask: 0b0100,
            ..CapState::default()
        };
        let mut dst = CapState {
            scope_id: 1,
            labels: 0b0001,
            restrict_mask: 0b0010,
            ..CapState::default()
        };
        admit_delta(
            &src,
            &mut dst,
            TARGET_CHILD,
            DeltaRequest {
                required_mask: AUTH_ADD_RESTRICTION
                    | AUTH_ADD_LABEL
                    | AUTH_NARROW_SCOPE
                    | AUTH_BIND_RULE,
                add_restrict_mask: 0b1000,
                add_label_mask: 0b0100,
                new_scope_id: 2,
                ..DeltaRequest::default()
            },
            scope_subset,
        )
        .unwrap();
        assert_eq!(dst.restrict_mask, 0b1010);
        assert_eq!(dst.labels, 0b0101);
        assert_eq!(dst.scope_id, 2);
    }

    #[test]
    fn rejects_non_monotonic_authority_gaps() {
        let src = CapState {
            authority_mask: AUTH_ADD_RESTRICTION,
            target_mask: TARGET_SELF,
            label_mask: 0b0001,
            ..CapState::default()
        };
        let base = CapState {
            scope_id: 4,
            labels: 0b0010,
            restrict_mask: 0b0100,
            ..CapState::default()
        };

        let mut dst = base;
        assert_eq!(
            admit_delta(
                &src,
                &mut dst,
                TARGET_CHILD,
                DeltaRequest::default(),
                scope_subset
            ),
            Err(AdmitError::TargetAuthority)
        );
        assert_eq!(dst, base);

        let mut dst = base;
        assert_eq!(
            admit_delta(
                &src,
                &mut dst,
                TARGET_SELF,
                DeltaRequest {
                    required_mask: AUTH_ADD_LABEL,
                    ..DeltaRequest::default()
                },
                scope_subset
            ),
            Err(AdmitError::UpdateAuthority)
        );

        let mut dst = base;
        let src_with_label_auth = CapState {
            authority_mask: AUTH_ADD_RESTRICTION | AUTH_ADD_LABEL,
            ..src
        };
        assert_eq!(
            admit_delta(
                &src,
                &mut dst,
                TARGET_SELF,
                DeltaRequest {
                    add_label_mask: 0b0001,
                    ..DeltaRequest::default()
                },
                scope_subset
            ),
            Err(AdmitError::UpdateAuthority)
        );

        let mut dst = base;
        assert_eq!(
            admit_delta(
                &src_with_label_auth,
                &mut dst,
                TARGET_SELF,
                DeltaRequest {
                    add_label_mask: 0b1000,
                    ..DeltaRequest::default()
                },
                scope_subset
            ),
            Err(AdmitError::LabelAuthority)
        );

        let mut dst = base;
        let src_with_scope_auth = CapState {
            authority_mask: AUTH_ADD_RESTRICTION | AUTH_NARROW_SCOPE,
            ..src
        };
        assert_eq!(
            admit_delta(
                &src_with_scope_auth,
                &mut dst,
                TARGET_SELF,
                DeltaRequest {
                    new_scope_id: 3,
                    ..DeltaRequest::default()
                },
                scope_subset
            ),
            Err(AdmitError::ScopeWiden)
        );
    }
    fn delta(
        required_mask: u64,
        add_restrict_mask: u64,
        add_label_mask: u64,
        add_gate_mask: u64,
        new_scope_id: u32,
    ) -> DeltaRequest {
        DeltaRequest {
            required_mask,
            add_restrict_mask,
            add_label_mask,
            add_gate_mask,
            new_scope_id,
            ..DeltaRequest::default()
        }
    }

    #[test]
    fn required_mask_combines_base_and_implied_authorities() {
        // `required_mask` ORs together the base authority mask with the
        // authority bits implied by the request's add-fields and scope
        // change. Each add-field independently implies its authority bit;
        // an empty request implies none. No base test pins this helper
        // directly.

        // An empty request implies no additional authority.
        assert_eq!(required_mask(delta(0, 0, 0, 0, 0)), 0);

        // The base required mask passes through verbatim.
        let base = AUTH_BIND_RULE | AUTH_DELEGATE;
        assert_eq!(required_mask(delta(base, 0, 0, 0, 0)), base);

        // Each add-field independently implies its authority bit.
        assert_eq!(required_mask(delta(0, 0b1, 0, 0, 0)), AUTH_ADD_RESTRICTION);
        assert_eq!(required_mask(delta(0, 0, 0b1, 0, 0)), AUTH_ADD_LABEL);
        assert_eq!(required_mask(delta(0, 0, 0, 0b1, 0)), AUTH_REQUIRE_GATE);
        assert_eq!(required_mask(delta(0, 0, 0, 0, 2)), AUTH_NARROW_SCOPE);

        // All add-fields combine with the base mask.
        assert_eq!(
            required_mask(delta(base, 0b1, 0b1, 0b1, 3)),
            base | AUTH_ADD_RESTRICTION | AUTH_ADD_LABEL | AUTH_REQUIRE_GATE | AUTH_NARROW_SCOPE
        );
    }
}
