#![forbid(unsafe_code)]

use fre_target_features::host;

fn main() {
    println!("{:#?}", host());
}
