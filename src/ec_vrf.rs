use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, constants::ED25519_BASEPOINT_POINT};
use sha2::{Sha512, Digest};

pub struct VRFOutput {
    gamma: EdwardsPoint,
    c: Scalar,
    s: Scalar,
    y: Vec<u8>
}

impl VRFOutput {
    fn hash_point(x: &Scalar) -> EdwardsPoint {
        EdwardsPoint::hash_from_bytes::<Sha512>(
            &x.to_bytes()
        )
    }

    fn hash_challenge(
        g: &EdwardsPoint,
        h: &EdwardsPoint,
        vk: &EdwardsPoint,
        gamma: &EdwardsPoint,
        gk: &EdwardsPoint,
        hk: &EdwardsPoint
    ) -> Scalar {
        Scalar::hash_from_bytes::<Sha512>(&[
            g.compress().to_bytes(),
            h.compress().to_bytes(),
            vk.compress().to_bytes(),
            gamma.compress().to_bytes(),
            gk.compress().to_bytes(),
            hk.compress().to_bytes()
        ].concat())
    }

    fn hash_output(gamma_f: &EdwardsPoint) -> Vec<u8> {
        Sha512::digest(&gamma_f.compress().to_bytes()).to_vec()
    }

    pub fn eval(vk: &EdwardsPoint, sk: &Scalar, x: &Scalar) -> Self {
        let h = Self::hash_point(&x);
        let gamma = h * sk;
        let mut rng = rand::rngs::ThreadRng::default();
        let k = Scalar::random(&mut rng);
        let gk = ED25519_BASEPOINT_POINT * k;
        let hk = h * k;
        let c = Self::hash_challenge(&ED25519_BASEPOINT_POINT, &h, &vk, &gamma, &gk, &hk);
        let s = k - c * sk;
        let y = Self::hash_output(&gamma.mul_by_cofactor());
        Self { gamma, c, s, y }
    }

    pub fn verify(&self, vk: &EdwardsPoint, x: &Scalar) -> bool {
        let u = vk * self.c + ED25519_BASEPOINT_POINT * self.s;
        let h = Self::hash_point(&x);
        // Trait for checking whether a point is on the curve.
        //
        // This trait is only for debugging/testing, since it should be
        // impossible for a `curve25519-dalek` user to construct an invalid
        // point.
        // pub(crate) trait ValidityCheck {
        //     /// Checks whether the point is on the curve. Not CT.
        //     fn is_valid(&self) -> bool;
        // }
        // if !self.gamma.is_valid() {
        //     return false;
        // }
        let v = self.gamma * self.c + h * self.s;
        let c_comp = Self::hash_challenge(&ED25519_BASEPOINT_POINT, &h, vk, &self.gamma, &u, &v);
        let y_comp = Self::hash_output(&self.gamma.mul_by_cofactor());
        self.c == c_comp && self.y == y_comp
    }
}

#[cfg(test)]
mod tests {
    // use std::time::{SystemTime, Duration};

    use curve25519_dalek::scalar::Scalar;
    use super::VRFOutput;

    #[test]
    fn test_valid() {
        let mut rng = rand::rngs::ThreadRng::default();
        let sk = Scalar::random(&mut rng);
        let vk = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * &sk;
        let x = Scalar::random(&mut rng);
        let output = VRFOutput::eval(&vk, &sk, &x);
        assert_eq!(true, output.verify(&vk, &x))
    }

//    fn bench_ec_vrf(repetition: usize) -> (Duration, Duration) {
//         let mut rng = rand::rngs::ThreadRng::default();
//         let sk = Scalar::random(&mut rng);
//         let vk = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * &sk;
//         let x = Scalar::random(&mut rng);

//         let eval_time = SystemTime::now();
//         (0..repetition).for_each(|_| {
//             VRFOutput::eval(&vk, &sk, &x);
//         });
//         let eval_time = SystemTime::now().duration_since(eval_time).unwrap();

//         let output = VRFOutput::eval(&vk, &sk, &x);
//         let verify_time = SystemTime::now();
//         (0..repetition).for_each(|_| {
//             assert_eq!(true, output.verify(&vk, &x));
//         });
//         let verify_time = SystemTime::now().duration_since(verify_time).unwrap();

//         (eval_time, verify_time)
//     }

//     #[test]
//     fn bench_ec_vrf_1000() {
//         let (eval_time, verify_time) = bench_ec_vrf(1000);
//         println!("Evaluate time    : {} ms", (eval_time.as_millis() as f32) / 1000.0);
//         println!("Verification time: {} ms", (verify_time.as_millis() as f32) / 1000.0);
//     }
}