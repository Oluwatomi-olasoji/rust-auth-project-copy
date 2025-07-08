use num_bigint::{BigUint, RandBigInt}; 
use rand;

pub struct ZKP {
    p: BigUint,
    q: BigUint, //order of the egrouo
    alpha: BigUint,
    beta: BigUint,

}

impl ZKP {
//output = n^exp mod p
pub fn exponentiate( n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    n.modpow(exponent,modulus)
}

//outpt = s = k - c * x mod q
pub fn solve( &self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
    if *k >= c * x {
        return (k - c * x).modpow(&BigUint::from(1u32), &self.q);
    }
    return &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q);
}

// the verfiy function verifies the solution by checking if 
//r1 = A^s * y1^c and r2 = B^s * y2^c

pub fn verify_solution(&self, r1: &BigUint, r2: &BigUint, y1: &BigUint, y2: &BigUint, c: &BigUint, s: &BigUint) -> bool {
   let condition1 = *r1 == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);
   let condition2 = *r2 == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);
   condition1 && condition2
}

pub fn generate_random_number_less_than(bound: &BigUint) -> BigUint {
    let mut rnge = rand::thread_rng();

    rnge.gen_biguint_below(bound)
}
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
        let zkp_new = ZKP {p:p.clone(), q, alpha: alpha.clone(), beta: beta.clone()};

        let x = BigUint::from(6u32); //the secret
        let k = BigUint::from(7u32); 

        let c = BigUint::from(4u32);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);
        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let s = zkp_new.solve(&k, &c, &x,);
        assert_eq!(s, BigUint::from(5u32));

        let result = zkp_new.verify_solution(&r1, &r2, &y1, &y2,  &c, &s);
        assert!(result);

        //false secret
        let x_fake = BigUint::from(7u32);
        let s_fake = zkp_new.solve(&k, &c, &x_fake);
        let result2 = zkp_new.verify_solution(&r1, &r2, &y1, &y2, &c, &s_fake);
        assert!(!result2)


    }

    #[test]
    fn testing_zkp_withrand() {
        let alpha = BigUint::from(4u32);  
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp_new = ZKP {p:p.clone(), q: q.clone(), alpha: alpha.clone(), beta: beta.clone()};;

        let x = BigUint::from(6u32); //the secret
        let k = ZKP::generate_random_number_less_than(&q);

        let c = ZKP::generate_random_number_less_than(&q);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 =ZKP:: exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);
       
        let s = zkp_new.solve(&k, &c, &x);
    

        let result = zkp_new.verify_solution(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result);

    

    }
    }

