//! Source-bound correctness producer for the qualified tag19 register-return
//! ABI2 route.
//!
//! This is deliberately separate from `sve_hardware_qualification`, whose
//! versioned rows exercise the retained Search-v1 result-slot ABI. A successful
//! invocation emits one exact receipt only after the selected-end register
//! image, publication, VL16 session, independent audit, portable/KIR
//! differentials, guard pages, and four-argument ABI canary all pass.

#[cfg(all(
    feature = "sve-hardware-qualification",
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod linux_aarch64 {
    use std::{env, error::Error, fs};

    use fre_jit_aarch64::{
        BackendVersion, EmitLimits, SelectedEndRegisterBackendV2, audit_selected_end_register_v2,
        emit_selected_end_register_v2,
    };
    use fre_jit_runtime::{
        PublicationLimits, native_selected_end_register_backend_support_v2,
        publish_selected_end_register_v2, qualification_with_guarded_haystack,
    };
    use fre_kernel_ir::{
        AnchorFlags, ExecutionLimits, SearchWindow, SelectedEnd, ValidateLimits,
        build_exact_literal,
    };
    use fre_kernels::{LiteralBuildLimits, LiteralPlan, LiteralSearchLimits, Window};
    use fre_target_features::TuningClass;

    const SCHEMA: &str = "fre-jit-tag19-selected-end-register-v2-qualification-v1";
    const LITERAL: &[u8; 16] = b"0123456789abcdef";
    const RANDOM_CASES: usize = 4096;
    const REQUIRED_PROFILE: &str = "linux-aarch64-arm-41-d84-vl16-release-v1";
    const CANARIES: [u64; 8] = [
        0x0808_0808_0808_0808,
        0x0909_0909_0909_0909,
        0x1010_1010_1010_1010,
        0x1111_1111_1111_1111,
        0x1212_1212_1212_1212,
        0x1313_1313_1313_1313,
        0x1414_1414_1414_1414,
        0x1515_1515_1515_1515,
    ];

    const SOURCE_COMMIT: Option<&str> = option_env!("FRE_TAG19_ABI2_SOURCE_COMMIT");
    const SOURCE_TREE: Option<&str> = option_env!("FRE_TAG19_ABI2_SOURCE_TREE");
    const SOURCE_ARCHIVE_SHA256: Option<&str> = option_env!("FRE_TAG19_ABI2_SOURCE_ARCHIVE_SHA256");
    const RESOURCE_COORDINATOR_SHA256: Option<&str> =
        option_env!("FRE_TAG19_ABI2_RESOURCE_COORDINATOR_SHA256");
    const RESOURCE_CUTOVER_SHA256: Option<&str> =
        option_env!("FRE_TAG19_ABI2_RESOURCE_CUTOVER_SHA256");
    const PROFILE: Option<&str> = option_env!("FRE_TAG19_ABI2_PROFILE");

    struct SourceBinding {
        commit: &'static str,
        tree: &'static str,
        archive: &'static str,
        build_receipt: String,
        resource_coordinator: &'static str,
        resource_cutover: &'static str,
        profile: &'static str,
    }

    pub(super) fn main() -> Result<(), Box<dyn Error>> {
        let source = source_binding()?;
        let cpu = require_host()?;
        let run_id = safe_runtime_token("FRE_TAG19_ABI2_RUN_ID")?;
        let instance_id = safe_runtime_token("FRE_TAG19_ABI2_INSTANCE_ID")?;
        let instance_type = safe_runtime_token("FRE_TAG19_ABI2_INSTANCE_TYPE")?;

        native_selected_end_register_backend_support_v2(
            SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16,
        )?;
        let program = build_exact_literal::<SelectedEnd>(
            LITERAL,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )?;
        let portable = LiteralPlan::new(LITERAL, LiteralBuildLimits::default())?;
        let image = emit_selected_end_register_v2(
            &program,
            SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16,
            EmitLimits::default(),
        )?;
        if image.backend() != SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16
            || image.backend_version() != BackendVersion::SEARCH_SVE16_V6
            || image.target().features.bits() != 3
            || image.literal_bytes() != 16
        {
            return Err("tag19 ABI2 emitter contract changed".into());
        }
        let audit = audit_selected_end_register_v2(&image)?;
        if audit.stores != 0 {
            return Err("tag19 ABI2 independent audit admitted a store".into());
        }
        let emitter_artifact = image.artifact_identity();
        let kernel = publish_selected_end_register_v2(&image, PublicationLimits::default())?;
        if kernel.backend() != SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16
            || kernel.literal_bytes() != 16
            || kernel.artifact_identity() != emitter_artifact
            || kernel
                .qualification_sve_vector_bytes_at_publication()
                .is_some()
            || kernel.qualification_required_thread_sve_vector_bytes() != Some(16)
        {
            return Err("tag19 ABI2 publication contract changed".into());
        }
        let session = kernel.begin_current_thread_session_for_literal_plan(&portable)?;
        let session_vl = session
            .qualification_validated_thread_sve_vector_bytes()
            .ok_or("tag19 ABI2 session did not validate its required VL")?;

        let comparisons = differential_corpus(&program, &portable, &session)?;
        guard_page_checks(&portable, &session)?;
        let mut late = vec![b'x'; 4096];
        let late_start = late
            .len()
            .checked_sub(LITERAL.len() + 31)
            .ok_or("late canary fixture is too short")?;
        late[late_start..late_start + LITERAL.len()].copy_from_slice(LITERAL);
        let canary_cases = [LITERAL.to_vec(), vec![b'x'; 4096], late];
        for haystack in &canary_cases {
            if !session.qualification_preserves_abi2_vector_callee_saved_lanes(
                haystack,
                SearchWindow::new(0, haystack.len()),
                LiteralSearchLimits::unlimited(),
                CANARIES,
            )? {
                return Err("tag19 ABI2 clobbered an AAPCS64 vector callee-saved lane".into());
            }
        }

        println!(
            "{SCHEMA}\tcandidate={}\ttree={}\tsource_archive_sha256={}\tbuild_receipt_sha256={}\tresource_coordinator_sha256={}\tresource_cutover_sha256={}\tprofile={}\trun_id={run_id}\tinstance_id={instance_id}\tinstance_type={instance_type}\tprocess_id={}\tcpu={cpu}\tbackend=19\tabi=SelectedEndRegisterV2\tartifact_sha256={emitter_artifact}\ttarget_feature_bits=3\tpublication_vl=none\tsession_vl={session_vl}\tindependent_audit=PASS\tstore_count={}\tforbidden_x4=PASS\tportable_oracle=PASS\tkernel_ir_oracle=PASS\tguard_pages=PASS\tabi2_vector_callee_saved_canary=PASS\tcomparisons={comparisons}\tstatus=PASS",
            source.commit,
            source.tree,
            source.archive,
            source.build_receipt,
            source.resource_coordinator,
            source.resource_cutover,
            source.profile,
            std::process::id(),
            audit.stores,
        );
        Ok(())
    }

    fn differential_corpus(
        program: &fre_kernel_ir::ValidatedProgram<SelectedEnd>,
        portable: &LiteralPlan,
        session: &fre_jit_runtime::PublishedSelectedEndRegisterThreadSessionV2<'_>,
    ) -> Result<usize, Box<dyn Error>> {
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        let mut comparisons = 0_usize;
        for (haystack, window) in [
            (&b""[..], SearchWindow::new(0, 0)),
            (&b"short"[..], SearchWindow::new(0, 5)),
            (&LITERAL[..], SearchWindow::new(0, LITERAL.len())),
            (&b"zz0123456789abcdefyy"[..], SearchWindow::new(0, 20)),
            (&b"zz0123456789abcdefyy"[..], SearchWindow::new(3, 20)),
            (
                &b"0123456789abcdefx0123456789abcdef"[..],
                SearchWindow::new(1, 33),
            ),
        ] {
            compare_one(program, portable, session, haystack, window)?;
            comparisons = comparisons.checked_add(1).ok_or("comparison overflow")?;
        }
        for case in 0..RANDOM_CASES {
            let len = 32_usize
                .checked_add(usize::try_from(next(&mut state) % 481)?)
                .ok_or("fixture length overflow")?;
            let alignment = case % 16;
            let mut storage = vec![0_u8; len.checked_add(16).ok_or("fixture allocation overflow")?];
            for byte in &mut storage {
                *byte = next(&mut state).to_le_bytes()[0];
            }
            let haystack = &mut storage[alignment..alignment + len];
            if case % 3 == 0 && len >= LITERAL.len() {
                let maximum = len - LITERAL.len();
                let start = usize::try_from(next(&mut state))? % (maximum + 1);
                haystack[start..start + LITERAL.len()].copy_from_slice(LITERAL);
            }
            let left = usize::try_from(next(&mut state))? % (len + 1);
            let right_span = len - left;
            let right = left + usize::try_from(next(&mut state))? % (right_span + 1);
            let window = SearchWindow::new(left, right);
            compare_one(program, portable, session, haystack, window)?;
            comparisons = comparisons.checked_add(1).ok_or("comparison overflow")?;
        }
        Ok(comparisons)
    }

    fn compare_one(
        program: &fre_kernel_ir::ValidatedProgram<SelectedEnd>,
        portable: &LiteralPlan,
        session: &fre_jit_runtime::PublishedSelectedEndRegisterThreadSessionV2<'_>,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<(), Box<dyn Error>> {
        let (portable_match, portable_accounting) = portable.find_window(
            haystack,
            Window::new(window.start(), window.end()),
            LiteralSearchLimits::unlimited(),
        )?;
        let kir_end = program
            .execute(haystack, window, ExecutionLimits::unlimited())?
            .into_output();
        let kir_match = kir_end.map(|end| (end - LITERAL.len(), end));
        let (native_match, native_accounting) =
            session.search(haystack, window, LiteralSearchLimits::unlimited())?;
        let native_match = native_match.map(|span| (span.start(), span.end()));
        if portable_match != kir_match
            || portable_match != native_match
            || portable_accounting != native_accounting
        {
            return Err("tag19 ABI2 differential mismatch".into());
        }
        Ok(())
    }

    fn guard_page_checks(
        portable: &LiteralPlan,
        session: &fre_jit_runtime::PublishedSelectedEndRegisterThreadSessionV2<'_>,
    ) -> Result<(), Box<dyn Error>> {
        let cases = [
            (vec![b'x'; 128], SearchWindow::new(0, 128)),
            (LITERAL.to_vec(), SearchWindow::new(0, LITERAL.len())),
            (
                [&b"x"[..], &LITERAL[..]].concat(),
                SearchWindow::new(0, LITERAL.len() + 1),
            ),
            (
                [&LITERAL[..], &b"x"[..]].concat(),
                SearchWindow::new(0, LITERAL.len() + 1),
            ),
            (b"short-miss".to_vec(), SearchWindow::new(0, 10)),
            (LITERAL.to_vec(), SearchWindow::new(1, LITERAL.len())),
        ];
        for (bytes, window) in &cases {
            for right_boundary in [false, true] {
                qualification_with_guarded_haystack(bytes, right_boundary, |haystack| {
                    let (expected, _) = portable
                        .find_window(
                            haystack,
                            Window::new(window.start(), window.end()),
                            LiteralSearchLimits::unlimited(),
                        )
                        .expect("guarded portable search");
                    let (actual, _) = session
                        .search(haystack, *window, LiteralSearchLimits::unlimited())
                        .expect("guarded ABI2 search");
                    assert_eq!(
                        actual.map(|span| (span.start(), span.end())),
                        expected,
                        "guarded ABI2 mismatch"
                    );
                })?;
            }
        }
        Ok(())
    }

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn source_binding() -> Result<SourceBinding, Box<dyn Error>> {
        let binding = SourceBinding {
            commit: required_hex(SOURCE_COMMIT, 40, "source commit")?,
            tree: required_hex(SOURCE_TREE, 40, "source tree")?,
            archive: required_hex(SOURCE_ARCHIVE_SHA256, 64, "source archive")?,
            build_receipt: runtime_hex("FRE_TAG19_ABI2_BUILD_RECEIPT_SHA256", 64)?,
            resource_coordinator: required_hex(
                RESOURCE_COORDINATOR_SHA256,
                64,
                "resource coordinator",
            )?,
            resource_cutover: required_hex(RESOURCE_CUTOVER_SHA256, 64, "resource cutover")?,
            profile: PROFILE.ok_or("qualification profile is not source-bound")?,
        };
        if binding.profile != REQUIRED_PROFILE {
            return Err("qualification profile is not the exact reviewed profile".into());
        }
        Ok(binding)
    }

    fn required_hex(
        value: Option<&'static str>,
        digits: usize,
        label: &str,
    ) -> Result<&'static str, Box<dyn Error>> {
        let value = value.ok_or_else(|| format!("{label} is not source-bound"))?;
        if value.len() != digits
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || value.bytes().all(|byte| byte == b'0')
        {
            return Err(format!("{label} is not one nonzero lowercase hex identity").into());
        }
        Ok(value)
    }

    fn safe_runtime_token(name: &str) -> Result<String, Box<dyn Error>> {
        let value = env::var(name)?;
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:@+-".contains(&byte))
        {
            return Err(format!("{name} is not one bounded safe token").into());
        }
        Ok(value)
    }

    fn runtime_hex(name: &str, digits: usize) -> Result<String, Box<dyn Error>> {
        let value = env::var(name)?;
        if value.len() != digits
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || value.bytes().all(|byte| byte == b'0')
        {
            return Err(format!("{name} is not one nonzero lowercase hex identity").into());
        }
        Ok(value)
    }

    fn require_host() -> Result<u32, Box<dyn Error>> {
        match fre_target_features::host().tuning() {
            TuningClass::ArmServer { cpu: Some(cpu) }
                if cpu.implementer == 0x41 && cpu.part == 0x0d84 => {}
            tuning => {
                return Err(format!(
                    "tag19 ABI2 qualification requires Arm 0x41/0xd84, got {tuning:?}"
                )
                .into());
            }
        }
        let affinity = fs::read_to_string("/proc/thread-self/status")?
            .lines()
            .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
            .map(str::trim)
            .ok_or("Cpus_allowed_list is absent")?;
        if affinity.contains(',') || affinity.contains('-') {
            return Err("qualification process must be pinned to exactly one CPU".into());
        }
        let cpu: u32 = affinity.parse()?;
        // SAFETY: `sched_getcpu` has no arguments and returns only the current
        // Linux scheduling CPU or a negative errno sentinel.
        let observed = unsafe { libc::sched_getcpu() };
        if observed < 0 || u32::try_from(observed)? != cpu {
            return Err("qualification process is not running on its sole allowed CPU".into());
        }
        Ok(cpu)
    }
}

#[cfg(all(
    feature = "sve-hardware-qualification",
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux_aarch64::main()
}

#[cfg(not(all(
    feature = "sve-hardware-qualification",
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
)))]
fn main() {
    panic!(
        "tag19 ABI2 qualification requires Linux AArch64 and \
         --features sve-hardware-qualification"
    );
}
