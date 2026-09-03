//! Split a passphrase 3-of-5, lose two shares, get it back.
//!
//! cargo run --example split

use honest_shamir::{reconstruct, split, Threshold};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let threshold = Threshold::new(3, 5).expect("3 <= 5");
    let secret = b"correct horse battery staple";

    let shares = split(secret, threshold).expect("the OS generator works");
    for share in &shares {
        println!("share {}: {}", share.index(), hex(share.bytes()));
    }

    // holders 2 and 4 are unreachable; 1, 3 and 5 meet the threshold
    let present = [shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let rebuilt = reconstruct(&present, threshold).expect("three distinct shares");
    println!("rebuilt: {}", String::from_utf8_lossy(&rebuilt));
    assert_eq!(rebuilt, secret);
}
