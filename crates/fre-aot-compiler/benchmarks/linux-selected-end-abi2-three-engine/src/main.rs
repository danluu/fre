//! Source-bound, non-authoritative Linux/AArch64 comparison of one exact
//! SelectedEnd ABI2 image used as linked AOT, strict-W^X JIT, and portable
//! exact-literal search.

use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    hint::black_box,
    marker::PhantomData,
    rc::Rc,
    time::{Duration, Instant},
};

use fre_jit_aarch64::{EmitLimits, SelectedEndRegisterBackendV2, emit_selected_end_register_v2};
use fre_jit_runtime::{
    PublicationLimits, PublishedSelectedEndRegisterThreadSessionV2, PublishedSelectedEndRegisterV2,
    native_host_capabilities, native_selected_end_register_backend_support_v2,
    publish_selected_end_register_v2,
};
use fre_kernel_ir::{
    AnchorFlags, CheckedSearchWindow, SearchWindow, SelectedEnd, ValidateLimits,
    build_exact_literal,
};
use fre_kernels::{LiteralBuildLimits, LiteralPlan, LiteralSearchLimits, LiteralSearchPreflight};
use fre_target_features::TuningClass;

mod linked {
    include!(concat!(env!("OUT_DIR"), "/linked_selected_end_v2.rs"));
}

type DynError = Box<dyn Error>;
type SpanValue = Option<(usize, usize)>;

const SCHEMA: &str = "fre-aot-selected-end-abi2-three-engine-v1";
const EVIDENCE_CLASS: &str = "diagnostic-nonpromotion";
const PROMOTION_AUTHORITY: &str = "absent";
const POST_LINK_OBSERVATION: &str = "pending-external-static-verifier";
const LITERAL: &[u8; 16] = b"0123456789abcdef";
const TAG21_FILTER_OFFSETS: [usize; 5] = [7, 6, 8, 5, 15];
const REQUIRED_PROFILE: &str = "linux-target-cpu-local-v1";
const WARMUP_CALLS: usize = 32;
const LIFECYCLE_WARMUP_CALLS: usize = 2;
const LIFECYCLE_ITERATIONS: usize = 8;
const PILOT_TIME: Duration = Duration::from_millis(20);
const TARGET_SAMPLE_TIME: Duration = Duration::from_millis(250);
const MIN_SAMPLE_TIME: Duration = Duration::from_millis(100);
const MAX_ITERATIONS: usize = 1 << 30;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Engine {
    Aot,
    Jit,
    Portable,
}

impl Engine {
    const ALL: [Self; 3] = [Self::Aot, Self::Jit, Self::Portable];

    const fn name(self) -> &'static str {
        match self {
            Self::Aot => "aot-tag21-entry-direct-abi2",
            Self::Jit => "jit-tag21-strict-wx-abi2",
            Self::Portable => "portable-exact-literal",
        }
    }

    const fn code_origin(self) -> &'static str {
        match self {
            Self::Aot => "offline-compiled-static-link",
            Self::Jit => "runtime-emitted-strict-wx",
            Self::Portable => "portable-preprocessed",
        }
    }
}

const ENGINE_ORDERS: [[Engine; 3]; 6] = [
    [Engine::Aot, Engine::Jit, Engine::Portable],
    [Engine::Aot, Engine::Portable, Engine::Jit],
    [Engine::Jit, Engine::Aot, Engine::Portable],
    [Engine::Jit, Engine::Portable, Engine::Aot],
    [Engine::Portable, Engine::Aot, Engine::Jit],
    [Engine::Portable, Engine::Jit, Engine::Aot],
];

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

    fn parse(value: &str) -> Result<Self, DynError> {
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

    fn parse(value: &str) -> Result<Self, DynError> {
        match value {
            "96" => Ok(Self::Tiny),
            "4k" => Ok(Self::FourKiB),
            "64k" => Ok(Self::SixtyFourKiB),
            "1m" => Ok(Self::OneMiB),
            _ => Err(format!("unknown size {value:?}").into()),
        }
    }
}

#[derive(Debug)]
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

/// Static linked-code owner. It exposes no call method without first opening
/// a current-thread tag21 session.
#[derive(Debug)]
struct AotLinked;

/// Same-thread AOT invocation capability.
///
/// `Rc` in the marker deliberately makes this token neither `Send` nor
/// `Sync`. Construction performs process-wide tag21 feature/tuning admission
/// and one current-thread `PR_SVE_GET_VL` observation. Hot calls perform no
/// feature or vector-length syscall.
#[derive(Debug)]
struct AotThreadSession<'owner> {
    _owner: &'owner AotLinked,
    _thread_bound: PhantomData<Rc<()>>,
}

impl AotLinked {
    fn begin_current_thread_session(&self) -> Result<AotThreadSession<'_>, DynError> {
        native_selected_end_register_backend_support_v2(
            SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
        )?;
        let capabilities = native_host_capabilities()?;
        if !capabilities.has_asimd()
            || !capabilities.has_sve()
            || !capabilities.has_sve2()
            || capabilities.sve_vector_bytes() != Some(16)
        {
            return Err(format!(
                "AOT thread session requires ASIMD+SVE+SVE2 and PR_SVE_GET_VL=16, got {capabilities:?}"
            )
            .into());
        }
        Ok(AotThreadSession {
            _owner: self,
            _thread_bound: PhantomData,
        })
    }
}

impl AotThreadSession<'_> {
    #[inline]
    fn search(&self, preflight: LiteralSearchPreflight<'_, '_>) -> Result<SpanValue, DynError> {
        if preflight.literal_bytes() != LITERAL.len() {
            return Err("AOT preflight literal width differs from linked artifact".into());
        }
        let checked = preflight.checked_window();
        let window = checked.window();
        let end_or_zero = linked::call_exact_linked_aot_selected_end_entry_v2(
            self,
            checked.haystack(),
            window.start(),
            window.end(),
        );
        decode_selected_end(end_or_zero, window)
    }

    fn search_qualification_wrapper(
        &self,
        preflight: LiteralSearchPreflight<'_, '_>,
    ) -> Result<SpanValue, DynError> {
        if preflight.literal_bytes() != LITERAL.len() {
            return Err("AOT wrapper preflight literal width differs from linked artifact".into());
        }
        let checked = preflight.checked_window();
        let window = checked.window();
        let end_or_zero = linked::call_exact_linked_aot_selected_end_qualification_wrapper_v2(
            self,
            checked.haystack(),
            window.start(),
            window.end(),
        );
        decode_selected_end(end_or_zero, window)
    }
}

struct Engines {
    portable: LiteralPlan,
    aot: AotLinked,
    jit: PublishedSelectedEndRegisterV2,
    jit_code_bytes: u32,
    jit_vector_instructions: u32,
}

struct EngineSessions<'engines> {
    engines: &'engines Engines,
    aot: AotThreadSession<'engines>,
    jit: PublishedSelectedEndRegisterThreadSessionV2<'engines>,
}

impl Engines {
    fn build() -> Result<Self, DynError> {
        native_selected_end_register_backend_support_v2(
            SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
        )?;
        let portable = LiteralPlan::new(LITERAL, LiteralBuildLimits::default())?;
        let program = build_exact_literal::<SelectedEnd>(
            LITERAL,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )?;
        let image = emit_selected_end_register_v2(
            &program,
            SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
            EmitLimits::default(),
        )?;
        if image.backend() != SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
            || image.literal_bytes() != u32::try_from(LITERAL.len())?
            || image.artifact_identity().as_bytes() != &linked::AOT_ARTIFACT_IDENTITY
        {
            return Err("runtime JIT image differs from exact linked AOT image".into());
        }
        let stats = image.stats();
        let jit = publish_selected_end_register_v2(&image, PublicationLimits::default())?;
        if jit.artifact_identity().as_bytes() != &linked::AOT_ARTIFACT_IDENTITY
            || jit.backend() != SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
            || jit.literal_bytes() != u32::try_from(LITERAL.len())?
        {
            return Err("strict-W^X publication differs from linked AOT artifact".into());
        }
        Ok(Self {
            portable,
            aot: AotLinked,
            jit,
            jit_code_bytes: stats.code_bytes,
            jit_vector_instructions: stats.vector_instructions,
        })
    }

    fn begin_sessions(&self) -> Result<EngineSessions<'_>, DynError> {
        Ok(EngineSessions {
            engines: self,
            aot: self.aot.begin_current_thread_session()?,
            jit: self.jit.begin_current_thread_session()?,
        })
    }
}

impl EngineSessions<'_> {
    fn preflight<'plan, 'haystack>(
        &'plan self,
        fixture: &'haystack Fixture,
    ) -> Result<LiteralSearchPreflight<'plan, 'haystack>, DynError> {
        let checked = CheckedSearchWindow::new(fixture.haystack(), fixture.window)
            .ok_or("fixture has an invalid checked window")?;
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
    ) -> Result<SpanValue, DynError> {
        match engine {
            Engine::Aot => self.aot.search(preflight),
            Engine::Jit => {
                let expected_accounting = preflight.accounting();
                let (matched, accounting) = self.jit.search_preflighted(preflight)?;
                if accounting != expected_accounting {
                    return Err("JIT changed authoritative scalar preflight accounting".into());
                }
                Ok(matched.map(|span| (span.start(), span.end())))
            }
            Engine::Portable => Ok(preflight.find()?),
        }
    }

    fn assert_equal(&self, fixture: &Fixture, category: &str) -> Result<u64, DynError> {
        let expected = independent_oracle(fixture)?;
        if expected != fixture.expected {
            return Err(format!(
                "{category}: fixture annotation differs from independent oracle: annotated={:?}, oracle={expected:?}",
                fixture.expected
            )
            .into());
        }
        let preflight = self.preflight(fixture)?;
        let portable = self.search(Engine::Portable, preflight)?;
        let jit = self.search(Engine::Jit, preflight)?;
        let aot = self.search(Engine::Aot, preflight)?;
        let wrapper = self.aot.search_qualification_wrapper(preflight)?;
        if portable != expected || jit != expected || aot != expected || wrapper != expected {
            return Err(format!(
                "{category}: expected={expected:?}, portable={portable:?}, jit={jit:?}, aot={aot:?}, qualification_wrapper={wrapper:?}"
            )
            .into());
        }
        Ok(4)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleSample {
    plan_ns: u128,
    emit_ns: u128,
    publish_ns: u128,
    preflight_ns: u128,
    session_ns: u128,
    first_call_ns: u128,
    total_ns: u128,
    checksum: u64,
}

fn main() -> Result<(), DynError> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("qualification") => qualification(&arguments[2..]),
        Some("cell") => cell(&arguments[2..]),
        Some("lifecycle") => lifecycle(&arguments[2..]),
        Some("metadata") if arguments.len() == 2 => {
            print_static_metadata();
            Ok(())
        }
        _ => Err(
            "usage: fre-aot-linux-selected-end-abi2-three-engine metadata | qualification SOURCE_COMMIT SOURCE_TREE RUN_ID INSTANCE_TYPE HELPER_SHA256 PROFILE | cell SIZE SCENARIO REPETITION SOURCE_COMMIT SOURCE_TREE RUN_ID INSTANCE_TYPE HELPER_SHA256 PROFILE | lifecycle SIZE SCENARIO REPETITION SOURCE_COMMIT SOURCE_TREE RUN_ID INSTANCE_TYPE HELPER_SHA256 PROFILE"
                .into(),
        ),
    }
}

fn qualification(arguments: &[String]) -> Result<(), DynError> {
    let identity = require_identity(arguments)?;
    let affinity_cpu = require_host()?;
    print_run_metadata(&identity, affinity_cpu);
    let engines = Engines::build()?;
    print_engine_metadata(&engines);
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
        "QUALIFICATION\t{SCHEMA}\tPASS\tcases={cases}\tcomparisons={comparisons}\taot_primary=exact-entry-direct\tqualification_wrapper=linked-and-exercised\tjit_publication=strict-wx\tjit_aot_artifact_equal=true\tvl16_sessions=aot-and-jit\tpost_link_observation={POST_LINK_OBSERVATION}\tpromotion_authority={PROMOTION_AUTHORITY}"
    );
    Ok(())
}

fn cell(arguments: &[String]) -> Result<(), DynError> {
    if arguments.len() != 9 {
        return Err("cell expects SIZE SCENARIO REPETITION plus six identity fields".into());
    }
    let size = Size::parse(&arguments[0])?;
    let scenario = Scenario::parse(&arguments[1])?;
    let repetition = parse_repetition(&arguments[2])?;
    let identity = require_identity(&arguments[3..])?;
    let affinity_cpu = require_host()?;
    let fixture = make_fixture(size.bytes(), scenario, repetition % 16)?;
    let order = ENGINE_ORDERS[repetition % ENGINE_ORDERS.len()];
    print_run_metadata(&identity, affinity_cpu);
    let engines = Engines::build()?;
    print_engine_metadata(&engines);
    let sessions = engines.begin_sessions()?;
    sessions.assert_equal(&fixture, "hot cell")?;
    let preflight = sessions.preflight(&fixture)?;
    for engine in Engine::ALL {
        for _ in 0..WARMUP_CALLS {
            black_box(sessions.search(engine, black_box(preflight))?);
        }
    }
    let mut iterations = BTreeMap::new();
    for engine in Engine::ALL {
        iterations.insert(engine, calibrate_hot(&sessions, engine, preflight)?);
    }
    println!(
        "CELL\t{SCHEMA}\tstage=hot\tstrategy=same-preflight-value-only\tsize={}\tscenario={}\trepetition={repetition}\torder={}\talignment={}\tsearched_bytes={}\twindow={}..{}\texpected={}\tartifact_identity={}\tbundle_identity={}\tsource_commit={}\tsource_tree={}\tpromotion_authority={PROMOTION_AUTHORITY}",
        size.name(),
        scenario.name(),
        format_order(order),
        fixture.haystack().as_ptr().addr() & 15,
        preflight.searched_bytes(),
        fixture.window.start(),
        fixture.window.end(),
        format_span(fixture.expected),
        hex(&linked::AOT_ARTIFACT_IDENTITY),
        hex(&linked::AOT_BUNDLE_IDENTITY),
        identity.source_commit,
        identity.source_tree,
    );
    for (position, engine) in order.into_iter().enumerate() {
        let engine_iterations = *iterations
            .get(&engine)
            .ok_or("calibration omitted an engine")?;
        let cpu_before = observed_cpu()?;
        let (elapsed, checksum) = time_hot(&sessions, engine, preflight, engine_iterations)?;
        let cpu_after = observed_cpu()?;
        require_stable_cpu(affinity_cpu, cpu_before, cpu_after)?;
        if elapsed < MIN_SAMPLE_TIME {
            return Err(format!(
                "{} hot sample shorter than {}ms: {}ns",
                engine.name(),
                MIN_SAMPLE_TIME.as_millis(),
                elapsed.as_nanos()
            )
            .into());
        }
        println!(
            "SAMPLE\t{SCHEMA}\tstage=hot\tengine={}\tcode_origin={}\tposition={position}\trepetition={repetition}\titerations={engine_iterations}\telapsed_ns={}\tchecksum={checksum}\tcpu_before={cpu_before}\tcpu_after={cpu_after}\tartifact_identity={}\tbundle_identity={}\tsource_commit={}\tsource_tree={}\tevidence_class={EVIDENCE_CLASS}\tpromotion_authority={PROMOTION_AUTHORITY}",
            engine.name(),
            engine.code_origin(),
            elapsed.as_nanos(),
            hex(&linked::AOT_ARTIFACT_IDENTITY),
            hex(&linked::AOT_BUNDLE_IDENTITY),
            identity.source_commit,
            identity.source_tree,
        );
    }
    Ok(())
}

fn lifecycle(arguments: &[String]) -> Result<(), DynError> {
    if arguments.len() != 9 {
        return Err("lifecycle expects SIZE SCENARIO REPETITION plus six identity fields".into());
    }
    let size = Size::parse(&arguments[0])?;
    let scenario = Scenario::parse(&arguments[1])?;
    let repetition = parse_repetition(&arguments[2])?;
    let identity = require_identity(&arguments[3..])?;
    let affinity_cpu = require_host()?;
    let fixture = make_fixture(size.bytes(), scenario, repetition % 16)?;
    let expected = independent_oracle(&fixture)?;
    if expected != fixture.expected {
        return Err("lifecycle fixture differs from independent oracle".into());
    }
    let order = ENGINE_ORDERS[repetition % ENGINE_ORDERS.len()];
    print_run_metadata(&identity, affinity_cpu);
    println!(
        "LIFECYCLE\t{SCHEMA}\tsize={}\tscenario={}\trepetition={repetition}\torder={}\titerations={LIFECYCLE_ITERATIONS}\taot_compile=offline-excluded\taot_link=offline-excluded\taot_runtime=plan+preflight+vl16-session+call\tjit_runtime=plan+emit+strict-wx-publication+preflight+vl16-session+call\tportable_runtime=plan+preflight+call\tartifact_identity={}\tbundle_identity={}\tsource_commit={}\tsource_tree={}\tpromotion_authority={PROMOTION_AUTHORITY}",
        size.name(),
        scenario.name(),
        format_order(order),
        hex(&linked::AOT_ARTIFACT_IDENTITY),
        hex(&linked::AOT_BUNDLE_IDENTITY),
        identity.source_commit,
        identity.source_tree,
    );
    for engine in Engine::ALL {
        for _ in 0..LIFECYCLE_WARMUP_CALLS {
            black_box(measure_lifecycle_once(engine, &fixture, expected)?);
        }
    }
    for (position, engine) in order.into_iter().enumerate() {
        let cpu_before = observed_cpu()?;
        let mut aggregate = LifecycleSample {
            plan_ns: 0,
            emit_ns: 0,
            publish_ns: 0,
            preflight_ns: 0,
            session_ns: 0,
            first_call_ns: 0,
            total_ns: 0,
            checksum: 0,
        };
        for iteration in 0..LIFECYCLE_ITERATIONS {
            let sample = measure_lifecycle_once(engine, &fixture, expected)?;
            aggregate.plan_ns = checked_add(aggregate.plan_ns, sample.plan_ns)?;
            aggregate.emit_ns = checked_add(aggregate.emit_ns, sample.emit_ns)?;
            aggregate.publish_ns = checked_add(aggregate.publish_ns, sample.publish_ns)?;
            aggregate.preflight_ns = checked_add(aggregate.preflight_ns, sample.preflight_ns)?;
            aggregate.session_ns = checked_add(aggregate.session_ns, sample.session_ns)?;
            aggregate.first_call_ns = checked_add(aggregate.first_call_ns, sample.first_call_ns)?;
            aggregate.total_ns = checked_add(aggregate.total_ns, sample.total_ns)?;
            aggregate.checksum = aggregate.checksum.rotate_left(9)
                ^ sample
                    .checksum
                    .wrapping_add(u64::try_from(iteration)?.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        }
        let cpu_after = observed_cpu()?;
        require_stable_cpu(affinity_cpu, cpu_before, cpu_after)?;
        black_box(aggregate.checksum);
        println!(
            "SAMPLE\t{SCHEMA}\tstage=lifecycle\tengine={}\tcode_origin={}\tposition={position}\trepetition={repetition}\titerations={LIFECYCLE_ITERATIONS}\tplan_ns={}\temit_ns={}\tpublish_ns={}\tpreflight_ns={}\tsession_ns={}\tfirst_call_ns={}\ttotal_ns={}\tchecksum={}\tcpu_before={cpu_before}\tcpu_after={cpu_after}\taot_compiler_cost_scope=offline-excluded\taot_linker_cost_scope=offline-excluded\tartifact_identity={}\tbundle_identity={}\tsource_commit={}\tsource_tree={}\tevidence_class={EVIDENCE_CLASS}\tpromotion_authority={PROMOTION_AUTHORITY}",
            engine.name(),
            engine.code_origin(),
            aggregate.plan_ns,
            aggregate.emit_ns,
            aggregate.publish_ns,
            aggregate.preflight_ns,
            aggregate.session_ns,
            aggregate.first_call_ns,
            aggregate.total_ns,
            aggregate.checksum,
            hex(&linked::AOT_ARTIFACT_IDENTITY),
            hex(&linked::AOT_BUNDLE_IDENTITY),
            identity.source_commit,
            identity.source_tree,
        );
    }
    let activation_plan = LiteralPlan::new(LITERAL, LiteralBuildLimits::default())?;
    let activation_checked = CheckedSearchWindow::new(fixture.haystack(), fixture.window)
        .ok_or("AOT activation fixture has invalid window")?;
    let activation_preflight = activation_plan
        .preflight_checked_window(activation_checked, LiteralSearchLimits::unlimited())?;
    for _ in 0..LIFECYCLE_WARMUP_CALLS {
        black_box(measure_aot_activation_once(activation_preflight, expected)?);
    }
    let activation_cpu_before = observed_cpu()?;
    let mut activation = LifecycleSample {
        plan_ns: 0,
        emit_ns: 0,
        publish_ns: 0,
        preflight_ns: 0,
        session_ns: 0,
        first_call_ns: 0,
        total_ns: 0,
        checksum: 0,
    };
    for iteration in 0..LIFECYCLE_ITERATIONS {
        let sample = measure_aot_activation_once(activation_preflight, expected)?;
        activation.session_ns = checked_add(activation.session_ns, sample.session_ns)?;
        activation.first_call_ns = checked_add(activation.first_call_ns, sample.first_call_ns)?;
        activation.total_ns = checked_add(activation.total_ns, sample.total_ns)?;
        activation.checksum = activation.checksum.rotate_left(9)
            ^ sample
                .checksum
                .wrapping_add(u64::try_from(iteration)?.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    }
    let activation_cpu_after = observed_cpu()?;
    require_stable_cpu(affinity_cpu, activation_cpu_before, activation_cpu_after)?;
    black_box(activation.checksum);
    println!(
        "SAMPLE\t{SCHEMA}\tstage=aot-activation\tengine={}\tcode_origin={}\trepetition={repetition}\titerations={LIFECYCLE_ITERATIONS}\tprepared_preflight=outside\tplan_ns=0\temit_ns=0\tpublish_ns=0\tpreflight_ns=0\tsession_ns={}\tfirst_call_ns={}\ttotal_ns={}\tchecksum={}\tcpu_before={activation_cpu_before}\tcpu_after={activation_cpu_after}\taot_compiler_cost_scope=offline-excluded\taot_linker_cost_scope=offline-excluded\tartifact_identity={}\tbundle_identity={}\tsource_commit={}\tsource_tree={}\tevidence_class={EVIDENCE_CLASS}\tpromotion_authority={PROMOTION_AUTHORITY}",
        Engine::Aot.name(),
        Engine::Aot.code_origin(),
        activation.session_ns,
        activation.first_call_ns,
        activation.total_ns,
        activation.checksum,
        hex(&linked::AOT_ARTIFACT_IDENTITY),
        hex(&linked::AOT_BUNDLE_IDENTITY),
        identity.source_commit,
        identity.source_tree,
    );
    Ok(())
}

fn measure_aot_activation_once(
    preflight: LiteralSearchPreflight<'_, '_>,
    expected: SpanValue,
) -> Result<LifecycleSample, DynError> {
    let total_started = Instant::now();
    let aot = AotLinked;
    let session_started = Instant::now();
    let session = aot.begin_current_thread_session()?;
    let session_ns = session_started.elapsed().as_nanos();
    let first_call_started = Instant::now();
    let actual = session.search(preflight)?;
    let first_call_ns = first_call_started.elapsed().as_nanos();
    if actual != expected {
        return Err(
            format!("AOT activation mismatch: expected={expected:?}, actual={actual:?}").into(),
        );
    }
    let total_ns = total_started.elapsed().as_nanos();
    let stage_sum = checked_add(session_ns, first_call_ns)?;
    if stage_sum > total_ns {
        return Err("AOT activation stage sum exceeds enclosing total".into());
    }
    Ok(LifecycleSample {
        plan_ns: 0,
        emit_ns: 0,
        publish_ns: 0,
        preflight_ns: 0,
        session_ns,
        first_call_ns,
        total_ns,
        checksum: span_checksum(actual, 0)?,
    })
}

fn measure_lifecycle_once(
    engine: Engine,
    fixture: &Fixture,
    expected: SpanValue,
) -> Result<LifecycleSample, DynError> {
    let total_started = Instant::now();
    let plan_started = Instant::now();
    let portable = LiteralPlan::new(LITERAL, LiteralBuildLimits::default())?;
    let program = match engine {
        Engine::Jit => Some(build_exact_literal::<SelectedEnd>(
            LITERAL,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )?),
        Engine::Aot | Engine::Portable => None,
    };
    let plan_ns = plan_started.elapsed().as_nanos();

    let emit_started = Instant::now();
    let image = program
        .as_ref()
        .map(|program| {
            emit_selected_end_register_v2(
                program,
                SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
                EmitLimits::default(),
            )
        })
        .transpose()?;
    let emit_ns = emit_started.elapsed().as_nanos();
    if image
        .as_ref()
        .is_some_and(|image| image.artifact_identity().as_bytes() != &linked::AOT_ARTIFACT_IDENTITY)
    {
        return Err("lifecycle JIT image differs from linked AOT artifact".into());
    }

    let publish_started = Instant::now();
    let jit = image
        .as_ref()
        .map(|image| publish_selected_end_register_v2(image, PublicationLimits::default()))
        .transpose()?;
    let publish_ns = publish_started.elapsed().as_nanos();

    let checked = CheckedSearchWindow::new(fixture.haystack(), fixture.window)
        .ok_or("lifecycle fixture has invalid window")?;
    let preflight_started = Instant::now();
    let preflight = portable.preflight_checked_window(checked, LiteralSearchLimits::unlimited())?;
    let preflight_ns = preflight_started.elapsed().as_nanos();

    let aot = AotLinked;
    let session_started = Instant::now();
    let aot_session = match engine {
        Engine::Aot => Some(aot.begin_current_thread_session()?),
        Engine::Jit | Engine::Portable => None,
    };
    let jit_session = jit
        .as_ref()
        .map(PublishedSelectedEndRegisterV2::begin_current_thread_session)
        .transpose()?;
    let session_ns = session_started.elapsed().as_nanos();

    let first_call_started = Instant::now();
    let actual = match engine {
        Engine::Aot => aot_session
            .as_ref()
            .ok_or("AOT lifecycle omitted its session")?
            .search(preflight)?,
        Engine::Jit => {
            let expected_accounting = preflight.accounting();
            let (matched, accounting) = jit_session
                .as_ref()
                .ok_or("JIT lifecycle omitted its session")?
                .search_preflighted(preflight)?;
            if accounting != expected_accounting {
                return Err("lifecycle JIT accounting mismatch".into());
            }
            matched.map(|span| (span.start(), span.end()))
        }
        Engine::Portable => preflight.find()?,
    };
    let first_call_ns = first_call_started.elapsed().as_nanos();
    if actual != expected {
        return Err(format!(
            "{} lifecycle mismatch: expected={expected:?}, actual={actual:?}",
            engine.name()
        )
        .into());
    }
    let total_ns = total_started.elapsed().as_nanos();
    let stage_sum = [
        plan_ns,
        emit_ns,
        publish_ns,
        preflight_ns,
        session_ns,
        first_call_ns,
    ]
    .into_iter()
    .try_fold(0_u128, checked_add)?;
    if stage_sum > total_ns {
        return Err("lifecycle stage sum exceeds enclosing total".into());
    }
    Ok(LifecycleSample {
        plan_ns,
        emit_ns,
        publish_ns,
        preflight_ns,
        session_ns,
        first_call_ns,
        total_ns,
        checksum: span_checksum(actual, 0)?,
    })
}

fn calibrate_hot(
    sessions: &EngineSessions<'_>,
    engine: Engine,
    preflight: LiteralSearchPreflight<'_, '_>,
) -> Result<usize, DynError> {
    let mut iterations = 1_usize;
    loop {
        let (elapsed, checksum) = time_hot(sessions, engine, preflight, iterations)?;
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

fn time_hot(
    sessions: &EngineSessions<'_>,
    engine: Engine,
    preflight: LiteralSearchPreflight<'_, '_>,
    iterations: usize,
) -> Result<(Duration, u64), DynError> {
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

fn decode_selected_end(end_or_zero: usize, window: SearchWindow) -> Result<SpanValue, DynError> {
    if end_or_zero == 0 {
        return Ok(None);
    }
    let start = end_or_zero
        .checked_sub(LITERAL.len())
        .ok_or("native selected end is shorter than the literal")?;
    if start < window.start() || end_or_zero > window.end() {
        return Err(format!(
            "native selected end {end_or_zero} is outside {}..{}",
            window.start(),
            window.end()
        )
        .into());
    }
    Ok(Some((start, end_or_zero)))
}

fn independent_oracle(fixture: &Fixture) -> Result<SpanValue, DynError> {
    let window = fixture.window;
    let searched = fixture
        .haystack()
        .get(window.start()..window.end())
        .ok_or("oracle window is invalid")?;
    Ok(searched
        .windows(LITERAL.len())
        .position(|candidate| candidate == LITERAL)
        .map(|relative| {
            let start = window.start() + relative;
            (start, start + LITERAL.len())
        }))
}

fn span_checksum(span: SpanValue, salt: u64) -> Result<u64, DynError> {
    let encoded = match span {
        None => 0x9e37_79b9_7f4a_7c15,
        Some((start, end)) => u64::try_from(start)?
            .rotate_left(17)
            .wrapping_add(u64::try_from(end)?.rotate_left(41))
            .wrapping_add(1),
    };
    Ok(encoded ^ salt.wrapping_mul(0xd6e8_feb8_6659_fd93))
}

fn make_fixture(bytes: usize, scenario: Scenario, alignment: usize) -> Result<Fixture, DynError> {
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
        return Err("fixture failed to realize requested alignment".into());
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

fn synthesize_filter_hits(haystack: &mut [u8], filter_offsets: [usize; 5]) -> Result<(), DynError> {
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

fn parse_repetition(value: &str) -> Result<usize, DynError> {
    let repetition = value.parse::<usize>()?;
    if repetition >= 120 {
        return Err("repetition must be in 0..119".into());
    }
    Ok(repetition)
}

fn require_identity(arguments: &[String]) -> Result<RunIdentity<'_>, DynError> {
    if arguments.len() != 6 {
        return Err("run identity expects six fields".into());
    }
    let identity = RunIdentity {
        source_commit: require_hex(&arguments[0], 40, "source commit")?,
        source_tree: require_hex(&arguments[1], 40, "source tree")?,
        run_id: &arguments[2],
        instance_type: &arguments[3],
        helper_sha256: require_hex(&arguments[4], 64, "helper SHA-256")?,
        profile: &arguments[5],
    };
    for (label, actual, expected) in [
        (
            "source commit",
            identity.source_commit,
            linked::BOUND_SOURCE_COMMIT,
        ),
        (
            "source tree",
            identity.source_tree,
            linked::BOUND_SOURCE_TREE,
        ),
        (
            "helper SHA-256",
            identity.helper_sha256,
            linked::BOUND_HELPER_SHA256,
        ),
        ("profile", identity.profile, linked::BOUND_PROFILE),
    ] {
        if actual != expected {
            return Err(format!(
                "compiled {label} differs from supplied value: compiled={expected:?}, supplied={actual:?}"
            )
            .into());
        }
    }
    if identity.profile != REQUIRED_PROFILE {
        return Err("unsupported qualification profile".into());
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

fn require_hex<'value>(
    value: &'value str,
    width: usize,
    label: &str,
) -> Result<&'value str, DynError> {
    if value.len() != width
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !value.bytes().any(|byte| byte != b'0')
    {
        return Err(format!(
            "{label} must be exactly {width} nonzero lowercase hexadecimal characters"
        )
        .into());
    }
    Ok(value)
}

fn require_host() -> Result<u32, DynError> {
    let affinity_cpu = require_single_cpu_affinity()?;
    native_selected_end_register_backend_support_v2(
        SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
    )?;
    let capabilities = native_host_capabilities()?;
    if !capabilities.has_asimd()
        || !capabilities.has_sve()
        || !capabilities.has_sve2()
        || capabilities.sve_vector_bytes() != Some(16)
    {
        return Err(format!(
            "requires OS-usable ASIMD+SVE+SVE2 with PR_SVE_GET_VL=16, got {capabilities:?}"
        )
        .into());
    }
    match fre_target_features::host().tuning() {
        TuningClass::ArmServer { cpu: Some(cpu) }
            if cpu.implementer == 0x41 && cpu.part == 0x0d84 => {}
        other => return Err(format!("requires Arm 0x41/0xd84, got {other:?}").into()),
    }
    require_homogeneous_d84()?;
    Ok(affinity_cpu)
}

fn require_homogeneous_d84() -> Result<(), DynError> {
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

fn require_single_cpu_affinity() -> Result<u32, DynError> {
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

fn observed_cpu() -> Result<u32, DynError> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let close = stat.rfind(") ").ok_or("malformed /proc/self/stat")?;
    Ok(stat[close + 2..]
        .split_whitespace()
        .nth(36)
        .ok_or("missing processor field")?
        .parse::<u32>()?)
}

fn require_stable_cpu(affinity_cpu: u32, before: u32, after: u32) -> Result<(), DynError> {
    if before != affinity_cpu || after != affinity_cpu {
        return Err(format!(
            "CPU affinity drift: affinity={affinity_cpu}, before={before}, after={after}"
        )
        .into());
    }
    Ok(())
}

fn print_run_metadata(identity: &RunIdentity<'_>, affinity_cpu: u32) {
    print_static_metadata();
    print_meta("run_id", identity.run_id);
    print_meta("instance_type", identity.instance_type);
    print_meta("affinity_cpu", affinity_cpu);
    print_meta("arm_cpu_implementer", "0x0041");
    print_meta("arm_cpu_part", "0x0d84");
    print_meta("asimd", true);
    print_meta("sve", true);
    print_meta("sve2", true);
    print_meta("sve_vector_bytes", 16);
    print_meta(
        "engine_order_rotation",
        "all-six-permutations-by-repetition",
    );
}

fn print_static_metadata() {
    print_meta("schema", SCHEMA);
    print_meta("evidence_class", EVIDENCE_CLASS);
    print_meta("promotion_authority", PROMOTION_AUTHORITY);
    print_meta("runtime_authority", "absent");
    print_meta("post_link_observation", POST_LINK_OBSERVATION);
    print_meta("source_commit", linked::BOUND_SOURCE_COMMIT);
    print_meta("source_tree", linked::BOUND_SOURCE_TREE);
    print_meta("helper_sha256", linked::BOUND_HELPER_SHA256);
    print_meta("profile", linked::BOUND_PROFILE);
    print_meta("artifact_identity", hex(&linked::AOT_ARTIFACT_IDENTITY));
    print_meta("compile_identity", hex(&linked::AOT_COMPILE_IDENTITY));
    print_meta(
        "implementation_object_identity",
        hex(&linked::AOT_IMPLEMENTATION_OBJECT_IDENTITY),
    );
    print_meta(
        "glue_object_identity",
        hex(&linked::AOT_GLUE_OBJECT_IDENTITY),
    );
    print_meta("bundle_identity", hex(&linked::AOT_BUNDLE_IDENTITY));
    print_meta("aot_wrapper_symbol", linked::WRAPPER_SYMBOL);
    print_meta("aot_entry_symbol", linked::ENTRY_SYMBOL);
    print_meta("aot_payload_symbol", linked::PAYLOAD_SYMBOL);
    print_meta("aot_metadata_symbol", linked::METADATA_SYMBOL);
    print_meta("post_link_contract_path", linked::POST_LINK_CONTRACT_PATH);
    print_meta(
        "implementation_object_path",
        linked::IMPLEMENTATION_OBJECT_PATH,
    );
    print_meta("direct_glue_object_path", linked::DIRECT_GLUE_OBJECT_PATH);
    print_meta("aot_primary_hot_route", "exact-entry-direct");
    print_meta(
        "qualification_wrapper",
        "linked-diagnostic-evidence-not-primary-hot-route",
    );
    print_meta("aot_compiler_cost_scope", "offline-excluded");
    print_meta("aot_linker_cost_scope", "offline-excluded");
    print_meta("hot_preflight", "once-outside-timer-shared-token");
    print_meta("hot_aot_vl16_session", "once-outside-timer");
    print_meta("hot_jit_vl16_session", "once-outside-timer");
    print_meta("lifecycle_aot_vl16_session", "inside-timer");
    print_meta("lifecycle_jit_vl16_session", "inside-timer");
}

fn print_engine_metadata(engines: &Engines) {
    print_meta("jit_aot_artifact_equal", true);
    print_meta("jit_code_bytes", engines.jit_code_bytes);
    print_meta("jit_vector_instructions", engines.jit_vector_instructions);
    print_meta("jit_publication", "strict-wx");
    print_meta("selected_end_return_encoding", "zero-or-absolute-end");
    print_meta("selected_end_result_slot_bytes", 0);
}

fn format_span(value: SpanValue) -> String {
    value.map_or_else(
        || "none".to_owned(),
        |(start, end)| format!("{start}..{end}"),
    )
}

fn format_order(order: [Engine; 3]) -> String {
    format!(
        "{},{},{}",
        order[0].name(),
        order[1].name(),
        order[2].name()
    )
}

fn print_meta(key: &str, value: impl std::fmt::Display) {
    println!("META\t{key}\t{value}");
}

fn checked_add(left: u128, right: u128) -> Result<u128, DynError> {
    left.checked_add(right)
        .ok_or_else(|| "timing accumulation overflow".into())
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
