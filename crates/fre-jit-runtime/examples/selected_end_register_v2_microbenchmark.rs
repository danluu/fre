//! Source-bound diagnostic for the Search tag21 out-slot ABI1 versus
//! register-return ABI2 transition.
//!
//! This binary deliberately emits `diagnostic-nonpromotion` evidence. It
//! separates correctness qualification, hot value-only cells, and cold-stage
//! accounting so a later controlled runner can retain the raw samples and
//! compute break-even points without treating an ad-hoc invocation as
//! production authority.

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod linux_aarch64 {
    use std::{
        collections::BTreeMap,
        error::Error,
        fs,
        hint::black_box,
        time::{Duration, Instant},
    };

    use fre_jit_aarch64::{
        BackendVersion, EmitLimits, SearchBackendPolicy, SelectedEndRegisterBackendV2,
        emit_selected_end_register_v2, emit_with_backend,
    };
    use fre_jit_runtime::{
        PublicationLimits, PublishedKernel, PublishedKernelThreadSession,
        PublishedSelectedEndRegisterThreadSessionV2, PublishedSelectedEndRegisterV2,
        native_host_capabilities, native_search_backend_support, publish,
        publish_selected_end_register_v2,
    };
    use fre_kernel_ir::{
        AnchorFlags, CheckedSearchWindow, SearchWindow, SelectedEnd, ValidateLimits,
        build_exact_literal,
    };
    use fre_kernels::{
        LiteralBuildLimits, LiteralPlan, LiteralSearchLimits, LiteralSearchPreflight,
    };
    use fre_target_features::TuningClass;

    const SCHEMA: &str = "fre-jit-selected-end-register-abi2-microbenchmark-v1";
    const EVIDENCE_CLASS: &str = "diagnostic-nonpromotion";
    const PROMOTION_AUTHORITY: &str = "absent";
    const LITERAL: &[u8; 16] = b"0123456789abcdef";
    const TAG21_FILTER_OFFSETS: [usize; 5] = [7, 6, 8, 5, 15];
    const WARMUP_CALLS: usize = 32;
    const PILOT_TIME: Duration = Duration::from_millis(20);
    const TARGET_SAMPLE_TIME: Duration = Duration::from_millis(250);
    const MIN_SAMPLE_TIME: Duration = Duration::from_millis(100);
    const MAX_ITERATIONS: usize = 1 << 30;
    const REQUIRED_PROFILE: &str = "linux-target-cpu-local-v1";

    const BOUND_SOURCE_COMMIT: Option<&str> = option_env!("FRE_JIT_ABI2_BENCH_SOURCE_COMMIT");
    const BOUND_SOURCE_TREE: Option<&str> = option_env!("FRE_JIT_ABI2_BENCH_SOURCE_TREE");
    const BOUND_HELPER_SHA256: Option<&str> = option_env!("FRE_JIT_ABI2_BENCH_HELPER_SHA256");
    const BOUND_PROFILE: Option<&str> = option_env!("FRE_JIT_ABI2_BENCH_PROFILE");

    type SpanValue = Option<(usize, usize)>;

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum Engine {
        Portable,
        LegacyTag21Abi1,
        RegisterTag21Abi2,
    }

    impl Engine {
        const ALL: [Self; 3] = [
            Self::Portable,
            Self::LegacyTag21Abi1,
            Self::RegisterTag21Abi2,
        ];

        const fn name(self) -> &'static str {
            match self {
                Self::Portable => "portable",
                Self::LegacyTag21Abi1 => "tag21-outslot-abi1",
                Self::RegisterTag21Abi2 => "tag21-register-abi2",
            }
        }

        const fn abi(self) -> &'static str {
            match self {
                Self::Portable => "portable",
                Self::LegacyTag21Abi1 => "1",
                Self::RegisterTag21Abi2 => "2",
            }
        }

        fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
            Self::ALL
                .into_iter()
                .find(|engine| engine.name() == value)
                .ok_or_else(|| format!("unknown engine {value:?}").into())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Scenario {
        Present,
        Absent,
        FiveFilterDenseAbsent,
        Tail,
        WindowPresent,
        WindowExcluded,
    }

    impl Scenario {
        const ALL: [Self; 6] = [
            Self::Present,
            Self::Absent,
            Self::FiveFilterDenseAbsent,
            Self::Tail,
            Self::WindowPresent,
            Self::WindowExcluded,
        ];

        const fn name(self) -> &'static str {
            match self {
                Self::Present => "present",
                Self::Absent => "absent",
                Self::FiveFilterDenseAbsent => "five-filter-dense-literal-absent",
                Self::Tail => "tail",
                Self::WindowPresent => "window-present",
                Self::WindowExcluded => "window-excluded",
            }
        }

        fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
            Self::ALL
                .into_iter()
                .find(|scenario| scenario.name() == value)
                .ok_or_else(|| format!("unknown scenario {value:?}").into())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Size {
        Tiny,
        FourKiB,
        SixtyFourKiB,
        OneMiB,
    }

    impl Size {
        const fn name(self) -> &'static str {
            match self {
                Self::Tiny => "96",
                Self::FourKiB => "4k",
                Self::SixtyFourKiB => "64k",
                Self::OneMiB => "1m",
            }
        }

        const fn bytes(self) -> usize {
            match self {
                Self::Tiny => 96,
                Self::FourKiB => 4 << 10,
                Self::SixtyFourKiB => 64 << 10,
                Self::OneMiB => 1 << 20,
            }
        }

        fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
            match value {
                "96" => Ok(Self::Tiny),
                "4k" => Ok(Self::FourKiB),
                "64k" => Ok(Self::SixtyFourKiB),
                "1m" => Ok(Self::OneMiB),
                _ => Err(format!("unknown size {value:?}").into()),
            }
        }
    }

    struct Fixture {
        storage: Vec<u8>,
        offset: usize,
        bytes: usize,
        window: SearchWindow,
        expected: SpanValue,
    }

    impl Fixture {
        fn haystack(&self) -> &[u8] {
            &self.storage[self.offset..self.offset + self.bytes]
        }
    }

    struct Engines {
        portable: LiteralPlan,
        legacy: PublishedKernel<SelectedEnd>,
        register: PublishedSelectedEndRegisterV2,
        legacy_identity: String,
        register_identity: String,
        legacy_code_bytes: u32,
        register_code_bytes: u32,
        legacy_vector_instructions: u32,
        register_vector_instructions: u32,
    }

    struct EngineSessions<'engines> {
        engines: &'engines Engines,
        legacy: PublishedKernelThreadSession<'engines, SelectedEnd>,
        register: PublishedSelectedEndRegisterThreadSessionV2<'engines>,
    }

    impl Engines {
        fn build() -> Result<Self, Box<dyn Error>> {
            native_search_backend_support(BackendVersion::SEARCH_SVE2_FIXED16_V2)?;
            let program = build_exact_literal::<SelectedEnd>(
                LITERAL,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )?;
            let portable = LiteralPlan::new(LITERAL, LiteralBuildLimits::default())?;
            let legacy_image = emit_with_backend(
                &program,
                SearchBackendPolicy::Sve2Fixed16V2,
                EmitLimits::default(),
            )?;
            let register_image = emit_selected_end_register_v2(
                &program,
                SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
                EmitLimits::default(),
            )?;
            if legacy_image.backend_version() != BackendVersion::SEARCH_SVE2_FIXED16_V2
                || register_image.backend_version() != BackendVersion::SEARCH_SVE2_FIXED16_V2
                || register_image.backend() != SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
                || register_image.literal_bytes() != 16
            {
                return Err("emitted tag21 image contract changed".into());
            }
            let legacy_identity = legacy_image.artifact_identity().to_string();
            let register_identity = register_image.artifact_identity().to_string();
            if legacy_identity == register_identity {
                return Err("ABI1 and ABI2 image identities were not domain-separated".into());
            }
            let legacy_stats = legacy_image.stats();
            let register_stats = register_image.stats();
            let legacy = publish::<SelectedEnd>(&legacy_image, PublicationLimits::default())?;
            let register =
                publish_selected_end_register_v2(&register_image, PublicationLimits::default())?;
            if legacy.sve_vector_bytes_at_publication() != Some(16)
                || !legacy.requires_current_thread_session()
                || register.backend() != SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
                || register.literal_bytes() != 16
            {
                return Err("published tag21 image contract changed".into());
            }
            Ok(Self {
                portable,
                legacy,
                register,
                legacy_identity,
                register_identity,
                legacy_code_bytes: legacy_stats.code_bytes,
                register_code_bytes: register_stats.code_bytes,
                legacy_vector_instructions: legacy_stats.vector_instructions,
                register_vector_instructions: register_stats.vector_instructions,
            })
        }

        fn begin_sessions(&self) -> Result<EngineSessions<'_>, Box<dyn Error>> {
            Ok(EngineSessions {
                engines: self,
                legacy: self.legacy.begin_current_thread_session()?,
                register: self.register.begin_current_thread_session()?,
            })
        }

        fn print_artifact_meta(&self) {
            print_meta("legacy_tag21_abi", 1);
            print_meta("legacy_tag21_artifact_identity", &self.legacy_identity);
            print_meta("legacy_tag21_code_bytes", self.legacy_code_bytes);
            print_meta(
                "legacy_tag21_vector_instructions",
                self.legacy_vector_instructions,
            );
            print_meta("register_tag21_abi", 2);
            print_meta("register_tag21_return_encoding", "zero-or-absolute-end");
            print_meta("register_tag21_artifact_identity", &self.register_identity);
            print_meta("register_tag21_code_bytes", self.register_code_bytes);
            print_meta(
                "register_tag21_vector_instructions",
                self.register_vector_instructions,
            );
        }
    }

    impl EngineSessions<'_> {
        fn preflight<'plan, 'haystack>(
            &'plan self,
            fixture: &'haystack Fixture,
        ) -> Result<LiteralSearchPreflight<'plan, 'haystack>, Box<dyn Error>> {
            let checked = CheckedSearchWindow::new(fixture.haystack(), fixture.window)
                .ok_or("fixture has an invalid window")?;
            Ok(self
                .engines
                .portable
                .preflight_checked_window(checked, LiteralSearchLimits::unlimited())?)
        }

        #[inline]
        fn search(
            &self,
            engine: Engine,
            preflight: LiteralSearchPreflight<'_, '_>,
        ) -> Result<SpanValue, Box<dyn Error>> {
            match engine {
                Engine::Portable => Ok(preflight.find()?),
                Engine::LegacyTag21Abi1 => {
                    let checked = preflight.checked_window();
                    selected_end_to_span(self.legacy.search_checked(checked)?, checked.window())
                }
                Engine::RegisterTag21Abi2 => {
                    let (matched, _accounting) = self.register.search_preflighted(preflight)?;
                    Ok(matched.map(|span| (span.start(), span.end())))
                }
            }
        }

        fn assert_equal(&self, fixture: &Fixture, category: &str) -> Result<u64, Box<dyn Error>> {
            let preflight = self.preflight(fixture)?;
            let portable = self.search(Engine::Portable, preflight)?;
            let legacy = self.search(Engine::LegacyTag21Abi1, preflight)?;
            let expected_accounting = preflight.accounting();
            let (register, accounting) = self.register.search_preflighted(preflight)?;
            if accounting != expected_accounting {
                return Err("ABI2 changed authoritative preflight accounting".into());
            }
            let register = register.map(|span| (span.start(), span.end()));
            if portable != fixture.expected
                || legacy != fixture.expected
                || register != fixture.expected
            {
                return Err(format!(
                    "{category} mismatch: expected={:?}, portable={portable:?}, legacy={legacy:?}, register={register:?}",
                    fixture.expected
                )
                .into());
            }
            Ok(3)
        }
    }

    #[derive(Debug)]
    struct RunIdentity<'argument> {
        source_commit: &'argument str,
        source_tree: &'argument str,
        run_id: &'argument str,
        instance_type: &'argument str,
        helper_sha256: &'argument str,
        profile: &'argument str,
    }

    pub(super) fn main() -> Result<(), Box<dyn Error>> {
        let arguments: Vec<String> = std::env::args().collect();
        match arguments.get(1).map(String::as_str) {
            Some("qualification") => qualification(&arguments[2..]),
            Some("cell") => cell(&arguments[2..]),
            Some("cold") => cold(&arguments[2..]),
            _ => Err(
                "usage: selected_end_register_v2_microbenchmark qualification SOURCE_COMMIT SOURCE_TREE RUN_ID INSTANCE_TYPE HELPER_SHA256 PROFILE | cell SIZE SCENARIO REPETITION ORDER_CSV SOURCE_COMMIT SOURCE_TREE RUN_ID INSTANCE_TYPE HELPER_SHA256 PROFILE | cold REPETITION ORDER_CSV SOURCE_COMMIT SOURCE_TREE RUN_ID INSTANCE_TYPE HELPER_SHA256 PROFILE"
                    .into(),
            ),
        }
    }

    fn qualification(arguments: &[String]) -> Result<(), Box<dyn Error>> {
        let identity = require_identity(arguments)?;
        let affinity_cpu = require_host()?;
        print_run_meta(&identity, affinity_cpu);
        let engines = Engines::build()?;
        engines.print_artifact_meta();
        let sessions = engines.begin_sessions()?;
        let mut comparisons = 0_u64;
        let mut cases = 0_u64;
        for size in [96, 127, 4 << 10] {
            for scenario in Scenario::ALL {
                for alignment in [0, 1, 7, 15] {
                    let fixture = make_fixture(size, scenario, alignment)?;
                    comparisons = comparisons
                        .checked_add(sessions.assert_equal(&fixture, "qualification")?)
                        .ok_or("qualification comparison overflow")?;
                    cases = cases.checked_add(1).ok_or("qualification case overflow")?;
                }
            }
        }
        println!(
            "QUALIFICATION\t{SCHEMA}\tPASS\tcases={cases}\tcomparisons={comparisons}\tguard_like_alignments=0,1,7,15\twindow_cases=true\tpromotion_authority={PROMOTION_AUTHORITY}"
        );
        Ok(())
    }

    fn cell(arguments: &[String]) -> Result<(), Box<dyn Error>> {
        if arguments.len() != 10 {
            return Err("cell expects ten arguments".into());
        }
        let size = Size::parse(&arguments[0])?;
        let scenario = Scenario::parse(&arguments[1])?;
        let repetition = parse_repetition(&arguments[2])?;
        let order = parse_order(&arguments[3])?;
        let identity = require_identity(&arguments[4..])?;
        let affinity_cpu = require_host()?;
        let alignment = repetition % 16;
        let fixture = make_fixture(size.bytes(), scenario, alignment)?;
        print_run_meta(&identity, affinity_cpu);
        let engines = Engines::build()?;
        engines.print_artifact_meta();
        let sessions = engines.begin_sessions()?;
        sessions.assert_equal(&fixture, "timed cell")?;
        let preflight = sessions.preflight(&fixture)?;
        for engine in Engine::ALL {
            for _ in 0..WARMUP_CALLS {
                black_box(sessions.search(engine, black_box(preflight))?);
            }
        }
        let mut calibrated = BTreeMap::new();
        for engine in Engine::ALL {
            calibrated.insert(engine, calibrate(&sessions, engine, preflight)?);
        }
        println!(
            "CELL\t{SCHEMA}\t{}\t{}\t{repetition}\t{}\t{alignment}\t{}\t{}\t{}\t{}\t{}",
            size.name(),
            scenario.name(),
            arguments[3],
            preflight.searched_bytes(),
            fixture.window.start(),
            fixture.window.end(),
            format_span(fixture.expected),
            fixture.haystack().as_ptr().addr() & 15,
        );
        for (position, engine) in order.into_iter().enumerate() {
            let iterations = *calibrated
                .get(&engine)
                .ok_or("calibration omitted an engine")?;
            let cpu_before = observed_cpu()?;
            let (elapsed, checksum) = time_engine(&sessions, engine, preflight, iterations)?;
            let cpu_after = observed_cpu()?;
            require_stable_cpu(affinity_cpu, cpu_before, cpu_after)?;
            if elapsed < MIN_SAMPLE_TIME {
                return Err(format!(
                    "{} sample was shorter than {}ms: {}ns",
                    engine.name(),
                    MIN_SAMPLE_TIME.as_millis(),
                    elapsed.as_nanos()
                )
                .into());
            }
            println!(
                "SAMPLE\t{SCHEMA}\t{}\t{}\t{}\t{}\t{repetition}\t{position}\t{iterations}\t{}\t{checksum}\t{cpu_before}\t{cpu_after}\t{EVIDENCE_CLASS}",
                engine.name(),
                engine.abi(),
                size.name(),
                scenario.name(),
                elapsed.as_nanos(),
            );
        }
        Ok(())
    }

    fn cold(arguments: &[String]) -> Result<(), Box<dyn Error>> {
        if arguments.len() != 8 {
            return Err("cold expects eight arguments".into());
        }
        let repetition = parse_repetition(&arguments[0])?;
        let order = parse_order(&arguments[1])?;
        let identity = require_identity(&arguments[2..])?;
        let affinity_cpu = require_host()?;
        let fixture = make_fixture(Size::FourKiB.bytes(), Scenario::Tail, repetition % 16)?;
        print_run_meta(&identity, affinity_cpu);

        let common_started = Instant::now();
        let program = build_exact_literal::<SelectedEnd>(
            LITERAL,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )?;
        let common_ir_ns = common_started.elapsed().as_nanos();
        let oracle = LiteralPlan::new(LITERAL, LiteralBuildLimits::default())?;
        let checked = CheckedSearchWindow::new(fixture.haystack(), fixture.window)
            .ok_or("cold fixture has an invalid window")?;
        let preflight =
            oracle.preflight_checked_window(checked, LiteralSearchLimits::unlimited())?;
        let expected = preflight.find()?;
        if expected != fixture.expected {
            return Err("cold fixture portable oracle mismatch".into());
        }
        println!(
            "COLD_COMMON\t{SCHEMA}\t{repetition}\tir_build_ns={common_ir_ns}\tsize={}\tscenario={}\talignment={}\texpected={}",
            Size::FourKiB.name(),
            Scenario::Tail.name(),
            repetition % 16,
            format_span(expected),
        );

        for (position, engine) in order.into_iter().enumerate() {
            let cpu_before = observed_cpu()?;
            let sample = measure_cold(engine, &program, preflight, expected)?;
            let cpu_after = observed_cpu()?;
            require_stable_cpu(affinity_cpu, cpu_before, cpu_after)?;
            println!(
                "COLD\t{SCHEMA}\t{}\t{}\t{repetition}\t{position}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{cpu_before}\t{cpu_after}\t{EVIDENCE_CLASS}",
                engine.name(),
                engine.abi(),
                sample.plan_build_ns,
                sample.emit_ns,
                sample.publish_ns,
                sample.session_ns,
                sample.first_call_ns,
                sample.total_ns,
                sample.code_bytes,
                sample.checksum,
            );
        }
        Ok(())
    }

    #[derive(Clone, Copy, Debug)]
    struct ColdSample {
        plan_build_ns: u128,
        emit_ns: u128,
        publish_ns: u128,
        session_ns: u128,
        first_call_ns: u128,
        total_ns: u128,
        code_bytes: u32,
        checksum: u64,
    }

    fn measure_cold(
        engine: Engine,
        program: &fre_kernel_ir::ValidatedProgram<SelectedEnd>,
        preflight: LiteralSearchPreflight<'_, '_>,
        expected: SpanValue,
    ) -> Result<ColdSample, Box<dyn Error>> {
        match engine {
            Engine::Portable => {
                let plan_started = Instant::now();
                let plan = LiteralPlan::new(LITERAL, LiteralBuildLimits::default())?;
                let plan_build_ns = plan_started.elapsed().as_nanos();
                let checked = preflight.checked_window();
                let call =
                    plan.preflight_checked_window(checked, LiteralSearchLimits::unlimited())?;
                let first_started = Instant::now();
                let actual = black_box(call.find()?);
                let first_call_ns = first_started.elapsed().as_nanos();
                require_expected(engine, actual, expected)?;
                Ok(ColdSample {
                    plan_build_ns,
                    emit_ns: 0,
                    publish_ns: 0,
                    session_ns: 0,
                    first_call_ns,
                    total_ns: sum_cold_stages(plan_build_ns, 0, 0, 0, first_call_ns)?,
                    code_bytes: 0,
                    checksum: span_checksum(actual, 0)?,
                })
            }
            Engine::LegacyTag21Abi1 => {
                let emit_started = Instant::now();
                let image = emit_with_backend(
                    program,
                    SearchBackendPolicy::Sve2Fixed16V2,
                    EmitLimits::default(),
                )?;
                let emit_ns = emit_started.elapsed().as_nanos();
                let code_bytes = image.stats().code_bytes;
                let publish_started = Instant::now();
                let kernel = publish::<SelectedEnd>(&image, PublicationLimits::default())?;
                let publish_ns = publish_started.elapsed().as_nanos();
                let session_started = Instant::now();
                let session = kernel.begin_current_thread_session()?;
                let session_ns = session_started.elapsed().as_nanos();
                let first_started = Instant::now();
                let actual = selected_end_to_span(
                    black_box(session.search_checked(preflight.checked_window())?),
                    preflight.checked_window().window(),
                )?;
                let first_call_ns = first_started.elapsed().as_nanos();
                require_expected(engine, actual, expected)?;
                Ok(ColdSample {
                    plan_build_ns: 0,
                    emit_ns,
                    publish_ns,
                    session_ns,
                    first_call_ns,
                    total_ns: sum_cold_stages(0, emit_ns, publish_ns, session_ns, first_call_ns)?,
                    code_bytes,
                    checksum: span_checksum(actual, 0)?,
                })
            }
            Engine::RegisterTag21Abi2 => {
                let emit_started = Instant::now();
                let image = emit_selected_end_register_v2(
                    program,
                    SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
                    EmitLimits::default(),
                )?;
                let emit_ns = emit_started.elapsed().as_nanos();
                let code_bytes = image.stats().code_bytes;
                let publish_started = Instant::now();
                let kernel =
                    publish_selected_end_register_v2(&image, PublicationLimits::default())?;
                let publish_ns = publish_started.elapsed().as_nanos();
                let session_started = Instant::now();
                let session = kernel.begin_current_thread_session()?;
                let session_ns = session_started.elapsed().as_nanos();
                let first_started = Instant::now();
                let (matched, accounting) = black_box(session.search_preflighted(preflight)?);
                let actual = black_box(matched.map(|span| (span.start(), span.end())));
                let first_call_ns = first_started.elapsed().as_nanos();
                if accounting != preflight.accounting() {
                    return Err("cold ABI2 accounting mismatch".into());
                }
                require_expected(engine, actual, expected)?;
                Ok(ColdSample {
                    plan_build_ns: 0,
                    emit_ns,
                    publish_ns,
                    session_ns,
                    first_call_ns,
                    total_ns: sum_cold_stages(0, emit_ns, publish_ns, session_ns, first_call_ns)?,
                    code_bytes,
                    checksum: span_checksum(actual, 0)?,
                })
            }
        }
    }

    fn sum_cold_stages(
        plan_build_ns: u128,
        emit_ns: u128,
        publish_ns: u128,
        session_ns: u128,
        first_call_ns: u128,
    ) -> Result<u128, Box<dyn Error>> {
        [
            plan_build_ns,
            emit_ns,
            publish_ns,
            session_ns,
            first_call_ns,
        ]
        .into_iter()
        .try_fold(0_u128, |total, stage| {
            total
                .checked_add(stage)
                .ok_or_else(|| "cold-stage total overflow".into())
        })
    }

    fn calibrate(
        sessions: &EngineSessions<'_>,
        engine: Engine,
        preflight: LiteralSearchPreflight<'_, '_>,
    ) -> Result<usize, Box<dyn Error>> {
        let mut iterations = 1_usize;
        loop {
            let (elapsed, checksum) = time_engine(sessions, engine, preflight, iterations)?;
            black_box(checksum);
            if elapsed >= PILOT_TIME {
                let target_ns = TARGET_SAMPLE_TIME.as_nanos();
                let elapsed_ns = elapsed.as_nanos().max(1);
                let scaled = u128::try_from(iterations)?
                    .checked_mul(target_ns)
                    .ok_or("calibration multiplication overflow")?
                    .checked_add(elapsed_ns - 1)
                    .ok_or("calibration rounding overflow")?
                    / elapsed_ns;
                return Ok(usize::try_from(scaled)?.clamp(iterations, MAX_ITERATIONS));
            }
            iterations = iterations
                .checked_mul(2)
                .ok_or("calibration iteration overflow")?;
            if iterations > MAX_ITERATIONS {
                return Err("calibration exceeded its iteration cap".into());
            }
        }
    }

    fn time_engine(
        sessions: &EngineSessions<'_>,
        engine: Engine,
        preflight: LiteralSearchPreflight<'_, '_>,
        iterations: usize,
    ) -> Result<(Duration, u64), Box<dyn Error>> {
        let started = Instant::now();
        let mut checksum = 0_u64;
        for iteration in 0..iterations {
            let matched = sessions.search(engine, black_box(preflight))?;
            checksum = checksum.wrapping_add(span_checksum(
                black_box(matched),
                u64::try_from(iteration)?,
            )?);
        }
        Ok((started.elapsed(), black_box(checksum)))
    }

    fn span_checksum(span: SpanValue, salt: u64) -> Result<u64, Box<dyn Error>> {
        let encoded = match span {
            None => 0x9e37_79b9_7f4a_7c15,
            Some((start, end)) => u64::try_from(start)?
                .rotate_left(17)
                .wrapping_add(u64::try_from(end)?.rotate_left(41))
                .wrapping_add(1),
        };
        Ok(encoded ^ salt.wrapping_mul(0xd6e8_feb8_6659_fd93))
    }

    fn selected_end_to_span(
        selected_end: Option<usize>,
        window: SearchWindow,
    ) -> Result<SpanValue, Box<dyn Error>> {
        selected_end
            .map(|end| {
                let start = end
                    .checked_sub(LITERAL.len())
                    .ok_or("legacy selected end is shorter than the literal")?;
                if start < window.start() || end > window.end() {
                    return Err("legacy selected end is outside the checked window".into());
                }
                Ok((start, end))
            })
            .transpose()
    }

    fn require_expected(
        engine: Engine,
        actual: SpanValue,
        expected: SpanValue,
    ) -> Result<(), Box<dyn Error>> {
        if actual != expected {
            return Err(format!(
                "{} cold result mismatch: expected={expected:?}, actual={actual:?}",
                engine.name()
            )
            .into());
        }
        Ok(())
    }

    fn make_fixture(
        bytes: usize,
        scenario: Scenario,
        alignment: usize,
    ) -> Result<Fixture, Box<dyn Error>> {
        if bytes < 96 || alignment >= 16 {
            return Err("fixture requires at least 96 bytes and alignment 0..15".into());
        }
        let storage_bytes = bytes.checked_add(15).ok_or("fixture allocation overflow")?;
        let mut storage = vec![b'x'; storage_bytes];
        let base_alignment = storage.as_ptr().addr() & 15;
        let offset = alignment
            .checked_add(16)
            .and_then(|value| value.checked_sub(base_alignment))
            .ok_or("fixture alignment overflow")?
            & 15;
        let haystack = &mut storage[offset..offset + bytes];
        if haystack.as_ptr().addr() & 15 != alignment {
            return Err("fixture failed to realize its requested alignment".into());
        }
        let mut window = SearchWindow::new(0, bytes);
        let expected = match scenario {
            Scenario::Present => {
                let start = (bytes - LITERAL.len()) / 2;
                haystack[start..start + LITERAL.len()].copy_from_slice(LITERAL);
                Some((start, start + LITERAL.len()))
            }
            Scenario::Absent => None,
            Scenario::FiveFilterDenseAbsent => {
                synthesize_filter_hits(haystack, TAG21_FILTER_OFFSETS)?;
                if haystack
                    .windows(LITERAL.len())
                    .any(|candidate| candidate == LITERAL)
                {
                    return Err("dense-absent fixture synthesized a literal".into());
                }
                None
            }
            Scenario::Tail => {
                let start = bytes - LITERAL.len();
                haystack[start..].copy_from_slice(LITERAL);
                Some((start, bytes))
            }
            Scenario::WindowPresent => {
                window = SearchWindow::new(11, bytes - 7);
                let width = window
                    .end()
                    .checked_sub(window.start())
                    .ok_or("window fixture underflow")?;
                let start = window.start() + (width - LITERAL.len()) / 2;
                haystack[start..start + LITERAL.len()].copy_from_slice(LITERAL);
                Some((start, start + LITERAL.len()))
            }
            Scenario::WindowExcluded => {
                haystack[..LITERAL.len()].copy_from_slice(LITERAL);
                window = SearchWindow::new(LITERAL.len() + 1, bytes);
                None
            }
        };
        Ok(Fixture {
            storage,
            offset,
            bytes,
            window,
            expected,
        })
    }

    fn synthesize_filter_hits(
        haystack: &mut [u8],
        filter_offsets: [usize; 5],
    ) -> Result<(), Box<dyn Error>> {
        let last = haystack
            .len()
            .checked_sub(LITERAL.len())
            .ok_or("dense fixture is shorter than the literal")?;
        for candidate in 0..=last {
            let compatible = filter_offsets.iter().all(|offset| {
                let index = candidate + *offset;
                haystack[index] == b'x' || haystack[index] == LITERAL[*offset]
            });
            if compatible {
                for offset in filter_offsets {
                    haystack[candidate + offset] = LITERAL[offset];
                }
            }
        }
        if !(0..=last).any(|candidate| {
            filter_offsets
                .iter()
                .all(|offset| haystack[candidate + *offset] == LITERAL[*offset])
        }) {
            return Err("dense fixture did not synthesize filter hits".into());
        }
        Ok(())
    }

    fn parse_repetition(value: &str) -> Result<usize, Box<dyn Error>> {
        let repetition = value.parse::<usize>()?;
        if repetition >= 120 {
            return Err("repetition must be in 0..119".into());
        }
        Ok(repetition)
    }

    fn parse_order(value: &str) -> Result<[Engine; 3], Box<dyn Error>> {
        let fields: Vec<&str> = value.split(',').collect();
        if fields.len() != 3 {
            return Err("order must contain three comma-separated engines".into());
        }
        let order = [
            Engine::parse(fields[0])?,
            Engine::parse(fields[1])?,
            Engine::parse(fields[2])?,
        ];
        let mut sorted = order.map(Engine::name);
        sorted.sort_unstable();
        if sorted != ["portable", "tag21-outslot-abi1", "tag21-register-abi2"] {
            return Err("order is not a permutation of all three engines".into());
        }
        Ok(order)
    }

    fn require_identity(arguments: &[String]) -> Result<RunIdentity<'_>, Box<dyn Error>> {
        if arguments.len() != 6 {
            return Err("run identity expects six arguments".into());
        }
        let identity = RunIdentity {
            source_commit: require_hex(&arguments[0], 40, "source commit")?,
            source_tree: require_hex(&arguments[1], 40, "source tree")?,
            run_id: &arguments[2],
            instance_type: &arguments[3],
            helper_sha256: require_hex(&arguments[4], 64, "helper SHA-256")?,
            profile: &arguments[5],
        };
        require_compiled_binding("source commit", identity.source_commit, BOUND_SOURCE_COMMIT)?;
        require_compiled_binding("source tree", identity.source_tree, BOUND_SOURCE_TREE)?;
        require_compiled_binding(
            "helper SHA-256",
            identity.helper_sha256,
            BOUND_HELPER_SHA256,
        )?;
        require_compiled_binding("profile", identity.profile, BOUND_PROFILE)?;
        if identity.profile != REQUIRED_PROFILE {
            return Err(format!("unsupported qualification profile {:?}", identity.profile).into());
        }
        if identity.run_id.is_empty()
            || !identity
                .run_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("run ID is empty or contains unsupported characters".into());
        }
        let instance_suffix = identity
            .instance_type
            .strip_prefix("c9g.")
            .or_else(|| identity.instance_type.strip_prefix("m9g."));
        if instance_suffix.is_none_or(str::is_empty)
            || !identity
                .instance_type
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return Err("instance type is outside the safe c9g/m9g grammar".into());
        }
        Ok(identity)
    }

    fn require_compiled_binding(
        name: &str,
        supplied: &str,
        compiled: Option<&str>,
    ) -> Result<(), Box<dyn Error>> {
        let compiled = compiled.ok_or_else(|| format!("binary lacks compiled {name} binding"))?;
        if compiled != supplied {
            return Err(format!(
                "compiled {name} differs from supplied value: compiled={compiled:?}, supplied={supplied:?}"
            )
            .into());
        }
        Ok(())
    }

    fn require_hex<'value>(
        value: &'value str,
        bytes: usize,
        label: &str,
    ) -> Result<&'value str, Box<dyn Error>> {
        if value.len() != bytes || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(
                format!("{label} must be exactly {bytes} lowercase hexadecimal bytes").into(),
            );
        }
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(format!("{label} must use lowercase hexadecimal").into());
        }
        Ok(value)
    }

    fn require_host() -> Result<u32, Box<dyn Error>> {
        let affinity_cpu = require_single_cpu_affinity()?;
        let capabilities = native_host_capabilities()?;
        if !capabilities.has_asimd()
            || !capabilities.has_sve()
            || !capabilities.has_sve2()
            || capabilities.sve_vector_bytes() != Some(16)
        {
            return Err(format!(
                "requires OS-usable ASIMD+SVE+SVE2 with VL16, got {capabilities:?}"
            )
            .into());
        }
        match fre_target_features::host().tuning() {
            TuningClass::ArmServer { cpu: Some(cpu) }
                if cpu.implementer == 0x41 && cpu.part == 0x0d84 => {}
            other => {
                return Err(format!("requires Arm 0x41/0xd84, got {other:?}").into());
            }
        }
        native_search_backend_support(BackendVersion::SEARCH_SVE2_FIXED16_V2)?;
        require_homogeneous_d84()?;
        Ok(affinity_cpu)
    }

    fn require_homogeneous_d84() -> Result<(), Box<dyn Error>> {
        let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
        let mut processors = 0_usize;
        for section in cpuinfo
            .split("\n\n")
            .filter(|section| !section.trim().is_empty())
        {
            let fields: BTreeMap<&str, &str> = section
                .lines()
                .filter_map(|line| line.split_once(':'))
                .map(|(key, value)| (key.trim(), value.trim()))
                .collect();
            if !fields.contains_key("processor") {
                continue;
            }
            processors = processors
                .checked_add(1)
                .ok_or("processor count overflow")?;
            let implementer = fields
                .get("CPU implementer")
                .ok_or("CPU section lacks implementer")?;
            let part = fields.get("CPU part").ok_or("CPU section lacks part")?;
            let features = fields
                .get("Features")
                .ok_or("CPU section lacks feature list")?;
            let feature_words: Vec<&str> = features.split_whitespace().collect();
            if *implementer != "0x41"
                || *part != "0xd84"
                || !["asimd", "sve", "sve2"]
                    .iter()
                    .all(|feature| feature_words.contains(feature))
            {
                return Err("host is not homogeneous Arm 0x41/0xd84 ASIMD+SVE+SVE2".into());
            }
        }
        if processors == 0 {
            return Err("no processor sections in /proc/cpuinfo".into());
        }
        Ok(())
    }

    fn require_single_cpu_affinity() -> Result<u32, Box<dyn Error>> {
        let status = fs::read_to_string("/proc/self/status")?;
        let allowed = status
            .lines()
            .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
            .map(str::trim)
            .ok_or("missing Cpus_allowed_list")?;
        if allowed.contains(',') || allowed.contains('-') {
            return Err(format!("requires one taskset CPU, got {allowed}").into());
        }
        let affinity_cpu = allowed.parse::<u32>()?;
        if observed_cpu()? != affinity_cpu {
            return Err("current CPU differs from taskset affinity".into());
        }
        Ok(affinity_cpu)
    }

    fn observed_cpu() -> Result<u32, Box<dyn Error>> {
        let stat = fs::read_to_string("/proc/self/stat")?;
        let close = stat.rfind(") ").ok_or("malformed /proc/self/stat")?;
        Ok(stat[close + 2..]
            .split_whitespace()
            .nth(36)
            .ok_or("missing processor field")?
            .parse::<u32>()?)
    }

    fn require_stable_cpu(
        affinity_cpu: u32,
        before: u32,
        after: u32,
    ) -> Result<(), Box<dyn Error>> {
        if before != affinity_cpu || after != affinity_cpu {
            return Err(format!(
                "CPU affinity drift: affinity={affinity_cpu}, before={before}, after={after}"
            )
            .into());
        }
        Ok(())
    }

    fn print_run_meta(identity: &RunIdentity<'_>, affinity_cpu: u32) {
        print_meta("schema", SCHEMA);
        print_meta("evidence_class", EVIDENCE_CLASS);
        print_meta("promotion_authority", PROMOTION_AUTHORITY);
        print_meta("source_commit", identity.source_commit);
        print_meta("source_tree", identity.source_tree);
        print_meta("run_id", identity.run_id);
        print_meta("instance_type", identity.instance_type);
        print_meta("helper_sha256", identity.helper_sha256);
        print_meta("profile", identity.profile);
        print_meta("affinity_cpu", affinity_cpu);
        print_meta("arch", "aarch64");
        print_meta("os", "linux");
        print_meta("arm_cpu_implementer", "0x0041");
        print_meta("arm_cpu_part", "0x0d84");
        print_meta("asimd", true);
        print_meta("sve", true);
        print_meta("sve2", true);
        print_meta("sve_vector_bytes", 16);
        print_meta("sve_lane_contract", "PTRUE-VL16");
        print_meta("timed_preflight", "outside");
        print_meta("timed_result_projection", "value-only");
        print_meta("cold_total", "sum-of-timed-stages-preflight-outside");
        print_meta("sample_order", "caller-supplied-permutation");
    }

    fn format_span(value: SpanValue) -> String {
        value.map_or_else(
            || "none".to_owned(),
            |(start, end)| format!("{start}..{end}"),
        )
    }

    fn print_meta(key: &str, value: impl std::fmt::Display) {
        println!("META\t{key}\t{value}");
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux_aarch64::main()
}

#[cfg(not(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
)))]
fn main() {
    eprintln!("selected_end_register_v2_microbenchmark requires little-endian Linux/AArch64");
    std::process::exit(2);
}
