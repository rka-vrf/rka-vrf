use curv::{elliptic::curves::{Scalar, Point, Curve}, cryptographic_primitives::hashing::DigestExt, BigInt};
use sha2::Digest;

pub struct InversionProof<C: Curve>{
    zt: Scalar<C>,
    zl: Scalar<C>,
    zr: Scalar<C>,
    x: Scalar<C>,
    t1_point: Point<C>
}

impl <C:Curve> InversionProof<C> {
    pub fn challenge(
        g: &Point<C>,
        h: &Point<C>,
        g_tilde: &Point<C>,
        h_tilde: &Point<C>,
        delta: &Point<C>,
        theta: &Point<C>,
        s1: &Point<C>,
        s2: &Point<C>,
        t0: &Point<C>,
        t1: &Point<C>
    ) -> Scalar<C> {
        Scalar::<C>::from_bigint(&sha2::Sha512::new().chain_points([
            g,
            h,
            g_tilde,
            h_tilde,
            delta,
            theta,
            s1,
            s2,
            t0,
            t1
        ]).result_bigint())
    }

    pub fn prove(g: &Point<C>, h: &Point<C>, g_tilde: &Point<C>, h_tilde: &Point<C>, gamma: &Scalar<C>, delta: &Point<C>, theta: &Point<C>) -> Self {
        let alpha = Scalar::<C>::random();
        let beta = Scalar::<C>::random();
        let s1 = g * &alpha;
        let s2 = h * &beta;
        let tau0 = Scalar::<C>::random();
        let tau1 = Scalar::<C>::random();
        let t0 = &alpha * &beta;
        let t1 = &alpha * &gamma.invert().unwrap() + &beta * gamma;
        let t0_point = g_tilde * &t0 + h_tilde * &tau0;
        let t1_point = g_tilde * &t1 + h_tilde * &tau1;
        let x = InversionProof::challenge(
            g,
            h,
            g_tilde,
            h_tilde,
            delta,
            theta,
            &s1,
            &s2,
            &t0_point,
            &t1_point
        );
        let zt = &tau1 * &x + &tau0;
        let zl = &alpha + &x * gamma;
        let zr = &beta + &x * gamma.invert().unwrap();
        Self {
            zt,
            zl,
            zr,
            x,
            t1_point,
        }
    }

    pub fn verify(&self, g: &Point<C>, h: &Point<C>, g_tilde: &Point<C>, h_tilde: &Point<C>, delta: &Point<C>, theta: &Point<C>) -> bool {
        let t0_point = 
            g_tilde * (&self.zl * &self.zr - &self.x * &self.x) +
            h_tilde * (&self.zt) + &self.t1_point * (-&self.x);
        let s1 = g * &self.zl + delta * (-&self.x);
        let s2 = h * &self.zr + theta * (-&self.x);
        let x_comp = InversionProof::challenge(
            g,
            h,
            g_tilde,
            h_tilde,
            delta,
            theta,
            &s1,
            &s2,
            &t0_point,
            &self.t1_point
        );
        return x_comp == self.x;
    }
}

pub struct VRFOutput<C: Curve> {
    y: BigInt,
    u: Point<C>,
    r: InversionProof<C>
}

impl <C: Curve> VRFOutput<C> {
    fn hash_point(vk: &Point<C>, x: &Point<C>) -> Point<C> {
        Point::<C>::generator() * Scalar::<C>::from_bigint(
            &sha2::Sha512::new().chain_points([
                vk, x
            ]).result_bigint()
        )
    }

    fn hash_output(x: &Point<C>, u: &Point<C>) -> BigInt {
        sha2::Sha512::new().chain_points([x, u]).result_bigint()
    }

    pub fn eval(
        g_tilde: &Point<C>,
        h_tilde: &Point<C>,
        vk: &Point<C>,
        sk: &Scalar<C>,
        x: &Point<C>
    ) -> Self {
        let base = Self::hash_point(vk, x);
        let u = &base * &sk.invert().unwrap();
        let r = InversionProof::prove(
            &Point::<C>::generator(),
            &base,
            g_tilde,
            h_tilde,
            &sk,
            &vk,
            &u
        );
        let y = Self::hash_output(x, &u);
        Self { y, u, r }
    }

    pub fn verify(
        &self,
        g_tilde: &Point<C>,
        h_tilde: &Point<C>,
        vk: &Point<C>,
        x: &Point<C>
    ) -> bool {
        self.y == Self::hash_output(x, &self.u) && self.r.verify(
            &Point::<C>::generator(),
            &Self::hash_point(vk, x),
            g_tilde,
            h_tilde,
            vk,
            &self.u
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, Duration};

    use curv::elliptic::curves::{Scalar, Ed25519, Point, Curve};

    use super::{InversionProof, VRFOutput};

    fn test_generic_inversion_proof<C: Curve>() {
        let g_tilde = Point::<C>::generator() * &Scalar::<C>::random();
        let h_tilde = Point::<C>::generator() * &Scalar::<C>::random();
        let gamma = Scalar::<C>::random();
        let delta = Point::<C>::generator() * &gamma;
        let theta = Point::<C>::base_point2() * &gamma.invert().unwrap();

        let proof = InversionProof::prove(&Point::<C>::generator(), Point::<C>::base_point2(), &g_tilde, &h_tilde, &gamma, &delta, &theta);
        assert_eq!(true, proof.verify(&Point::<C>::generator(), Point::<C>::base_point2(), &g_tilde, &h_tilde, &delta, &theta))
    }

    fn test_generic_vrf<C: Curve>() {
        let sk = Scalar::<C>::random();
        let vk = Point::<C>::generator() * &sk;
        let x = Point::<C>::generator() * &Scalar::<C>::random();

        let g_tilde = Point::<C>::generator() * &Scalar::<C>::random();
        let h_tilde = Point::<C>::generator() * &Scalar::<C>::random();

        let output = VRFOutput::eval(&g_tilde, &h_tilde, &vk, &sk, &x);
        assert_eq!(true, output.verify(&g_tilde, &h_tilde, &vk, &x));
    }

    #[test]
    fn test_ed25519_inversion_proof() {
        test_generic_inversion_proof::<Ed25519>()
    }

    #[test]
    fn test_ed25519_vrf() {
        test_generic_vrf::<Ed25519>()
    }

    fn bench_generic_vrf<C: Curve>(repetition: usize) -> (Duration, Duration){
        let sk = Scalar::<C>::random();
        let vk = Point::<C>::generator() * &sk;
        let x = Point::<C>::generator() * &Scalar::<C>::random();

        let g_tilde = Point::<C>::generator() * &Scalar::<C>::random();
        let h_tilde = Point::<C>::generator() * &Scalar::<C>::random();

        let eval_time = SystemTime::now();
        (0..repetition).for_each(|_| {
            VRFOutput::eval(&g_tilde, &h_tilde, &vk, &sk, &x);
        });
        let eval_time = SystemTime::now().duration_since(eval_time).unwrap();

        let output = VRFOutput::eval(&g_tilde, &h_tilde, &vk, &sk, &x);
        let verify_time = SystemTime::now();
        (0..repetition).for_each(|_| {
            assert_eq!(true, output.verify(&g_tilde, &h_tilde, &vk, &x));
        });
        let verify_time = SystemTime::now().duration_since(verify_time).unwrap();
        
        (eval_time, verify_time)
    }

    #[test]
    fn bench_ed25519_vrf_1000() {
        let (eval_time, verify_time) = bench_generic_vrf::<Ed25519>(1000);
        println!("Evaluate time    : {} ms", (eval_time.as_millis() as f32) / 1000.0);
        println!("Verification time: {} ms", (verify_time.as_millis() as f32) / 1000.0);
    }
}