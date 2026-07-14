use fre_jit_cache::CacheLimits;

fn main() {
    println!("max_entries,max_in_flight,max_live_mappings,bookkeeping_reservation_bytes");
    for (entries, flights, live) in [
        (0, 0, 0),
        (1, 1, 1),
        (16, 2, 32),
        (256, 8, 512),
        (4_096, 64, 8_192),
    ] {
        let limits = CacheLimits {
            max_entries: entries,
            max_in_flight_builds: flights,
            max_live_mappings: live,
            ..CacheLimits::default()
        };
        let bytes = limits
            .required_bookkeeping_bytes()
            .expect("bounded diagnostic row");
        println!("{entries},{flights},{live},{bytes}");
    }
}
