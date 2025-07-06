use num_bigint::BigUint; 

//output = n^exp mod p
pub fn exponentiate( n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    n.modpow(exponent,modulus)
}

//outpt = s = k - c * x mod q
pub fn solve( k: &BigUint, c: &BigUint, x: &BigUint, q: &BigUint) -> BigUint {
    if *k >= c * x {
        return (k - c * x).modpow(&BigUint::from(1u32), q);
    }
    return q - (c * x - k).modpow(&BigUint::from(1u32), q);
}