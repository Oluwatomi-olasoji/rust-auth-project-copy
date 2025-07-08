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

// the verfiy function verifies the solution by checking if 
//r1 = A^s * y1^c and r2 = B^s * y2^c

pub fn verify_solution( r1: &BigUint, r2: &BigUint, y1: &BigUint, y2: &BigUint, A: &BigUint, B: &BigUint , c: &BigUint, s: &BigUint, p: &BigUint) -> bool {
   let condition1 = *r1 == (A.modpow(s, p) * y1.modpow(c, p)).modpow(&BigUint::from(1u32), &p);
   let condition2 = *r2 == (B.modpow(s, p) * y2.modpow(c, p)).modpow(&BigUint::from(1u32), &p);
   condition1 && condition2
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn testing_zkp() {
        let alpha = BigUint::from(4u32);  
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);

        let x = BigUint::from(6u32); //the secret
        let k = BigUint::from(7u32); 

        let c = BigUint::from(4u32);

        let y1 = exponentiate(&alpha, &x, &p);
        let y2 = exponentiate(&beta, &x, &p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = exponentiate(&alpha, &k, &p);
        let r2 = exponentiate(&beta, &k, &p);
        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let s = solve(&k, &c, &x, &q);
        assert_eq!(s, BigUint::from(5u32));

        let result = verify_solution(&r1, &r2, &y1, &y2, &alpha, &beta, &c, &s, &p);
        assert!(result);


    }
    }

