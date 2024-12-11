use super::TestGenerators;
use cait_sith::protocol::Participant;
use k256::elliptic_curve::Field;
use k256::Scalar;

#[test]
fn benchmark_single_threaded_presignature_generation() {
    let generator = TestGenerators::new(10, 7);
    let keygens = generator.make_keygens();
    let triple0s = generator.make_triples();
    let triple1s = generator.make_triples();

    let start_time = std::time::Instant::now();
    const COUNT: usize = 1000;
    for _ in 0..COUNT {
        let _ = generator.make_presignatures(&triple0s, &triple1s, &keygens);
    }
    let end_time = std::time::Instant::now();
    println!(
        "Time taken per presignature: {:?}",
        (end_time - start_time) / COUNT as u32
    );
}

#[test]
fn benchmark_single_threaded_signature_generation() {
    let generator = TestGenerators::new(10, 7);
    let keygens = generator.make_keygens();
    let triple0s = generator.make_triples();
    let triple1s = generator.make_triples();
    let presignatures = generator.make_presignatures(&triple0s, &triple1s, &keygens);

    let start_time = std::time::Instant::now();
    const COUNT: usize = 1000;
    for _ in 0..COUNT {
        let _ = generator.make_signature(
            &presignatures,
            keygens[&Participant::from(0)].public_key,
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
        );
    }
    let end_time = std::time::Instant::now();
    println!(
        "Time taken per signature: {:?}",
        (end_time - start_time) / COUNT as u32
    );
}
