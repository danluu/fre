use fre_aot_static_runtime::{
    RawStaticSearchSpanAdoptionOutputV1, StaticSearchSpanAdoptionErrorV1,
    adopt_linked_static_search_span_family_qualification_v1,
};

#[allow(
    unsafe_code,
    reason = "generated declarations name one receipt-bound private family glue symbol"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

#[allow(
    unsafe_code,
    reason = "the smoke invokes exactly one receipt-bound private family glue and requires fail-closed adoption"
)]
fn main() {
    // SAFETY: the closure invokes only the generated receipt-bound family
    // glue. The empty private family table must refuse before inspecting any
    // final-image pointer or executing native code.
    let result = unsafe {
        adopt_linked_static_search_span_family_qualification_v1(
            |output: *mut RawStaticSearchSpanAdoptionOutputV1| generated::invoke(output),
        )
    };
    assert!(matches!(
        result,
        Err(StaticSearchSpanAdoptionErrorV1::NoQualifiedStaticSearchSpanRow)
    ));
    println!("tag25_static_link=true");
    println!("private_family_adoption=no-qualified-row");
    println!("native_entry_executed=false");
}
