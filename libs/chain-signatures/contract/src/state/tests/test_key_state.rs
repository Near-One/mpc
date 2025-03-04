use std::collections::BTreeMap;

use crate::state::{
    key_state::{DKGThreshold, KeyStateProposal, Threshold, ThresholdParameters},
    tests::test_utils::gen_participants,
};

#[test]
fn test_constructor() {
    let n = 40;
    let min_threshold = 24; // 60%
    let participant_set_a = gen_participants(n);
    for k in 1..min_threshold {
        let invalid_threshold = Threshold::new(k as u64);
        assert!(ThresholdParameters::new(participant_set_a.clone(), invalid_threshold).is_err());
    }
    for k in min_threshold..(n + 1) {
        let valid_threshold = Threshold::new(k as u64);
        assert!(ThresholdParameters::new(participant_set_a.clone(), valid_threshold).is_ok());
    }

    let tpt = min_threshold;
    let tp =
        ThresholdParameters::new(participant_set_a.clone(), Threshold::new(tpt as u64)).unwrap();
    assert!(tp.threshold().value() == (tpt as u64));
    assert!(tp.n_participants() == (n as u64));
    for account_id in participant_set_a.keys() {
        assert!(tp.is_participant(account_id));
    }

    let mut res = BTreeMap::new();
    for i in 0..n {
        let p = tp.participant_by_idx(i as u64).unwrap();
        assert!(tp.participant_idx(&p).unwrap() == (i as u64));
        let info = participant_set_a.get(&p).unwrap();
        assert!(res.insert(p, info.clone()).is_none());
    }
    assert!(res == *tp.participants());

    for ket in tpt..(n + 1) {
        assert!(KeyStateProposal::new(tp.clone(), DKGThreshold::new(ket as u64)).is_ok());
    }
}
