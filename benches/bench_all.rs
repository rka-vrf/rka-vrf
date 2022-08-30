use criterion::{criterion_main, criterion_group, Criterion};
use curv::elliptic::curves::{Ed25519, Point};

criterion_group!(benches, ec_vrf, rka_vrf);
criterion_main!(benches);

fn ec_vrf(c: &mut Criterion) {
    let mut rng = rand::rngs::ThreadRng::default();
    let sk = curve25519_dalek::scalar::Scalar::random(&mut rng);
    let vk = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * &sk;
    let x = curve25519_dalek::scalar::Scalar::random(&mut rng);

    c.bench_function(
        "EC-VRF evaluation",
        |b| b.iter(
            || vrf::ec_vrf::VRFOutput::eval(&vk, &sk, &x)
        )
    );

    let output = vrf::ec_vrf::VRFOutput::eval(&vk, &sk, &x);
    c.bench_function(
        "EC-VRF verification",
        |b| b.iter(
            || assert_eq!(true, output.verify(&vk, &x))
        )
    );
}

fn rka_vrf(c: &mut Criterion) {
    let sk = curv::elliptic::curves::Scalar::<Ed25519>::random();
    let vk = Point::<Ed25519>::generator() * &sk;
    let x = Point::<Ed25519>::generator() * &curv::elliptic::curves::Scalar::<Ed25519>::random();

    let g_tilde = Point::<Ed25519>::generator() * &curv::elliptic::curves::Scalar::<Ed25519>::random();
    let h_tilde = Point::<Ed25519>::generator() * &curv::elliptic::curves::Scalar::<Ed25519>::random();

    c.bench_function(
        "RKA-VRF evaluation",
        |b| b.iter(
            || vrf::rka_vrf::VRFOutput::eval(&g_tilde, &h_tilde, &vk, &sk, &x)
        )
    );

    let output = vrf::rka_vrf::VRFOutput::eval(&g_tilde, &h_tilde, &vk, &sk, &x);
    c.bench_function(
        "RKA-VRF verification",
        |b| b.iter(
            || assert_eq!(true, output.verify(&g_tilde, &h_tilde, &vk, &x))
        )
    );
}