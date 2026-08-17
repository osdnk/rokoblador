use rokoko::common::ring_arithmetic::RingElement;
use rokoko::protocol::config::SumcheckRoundProof;

use crate::labrador::ProofHandle;

pub struct RokokoHandoff {
    pub rc_commitment: Vec<RingElement>,
    pub proof: SumcheckRoundProof,
    pub claims: Vec<RingElement>,
}

pub struct CombinedProof {
    pub rokoko: RokokoHandoff,
    pub per_vector_betasq: Vec<u64>,
    pub labrador: ProofHandle,
}
