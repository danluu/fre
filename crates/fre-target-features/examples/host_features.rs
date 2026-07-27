#![forbid(unsafe_code)]

use fre_target_features::{dispatch_profile, host};

fn main() {
    println!("dispatch_profile={}", dispatch_profile().name());
    println!("{:#?}", host());
}
