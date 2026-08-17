use std::num::NonZeroUsize;

use rokoko::protocol::boundary::{BoundaryCapture, ProverBoundary, VerifierBoundary};
use rokoko::protocol::config::{Config, SumcheckConfig, CONFIG};
use rokoko::protocol::crs::{VerifierCRS, CRS};
use rokoko::protocol::evaluation_point_sampler::{sample_initial_evaluation_points, InitialEvaluationPoints};
use rokoko::protocol::parties::commiter::commit;
use rokoko::protocol::parties::prover::prover_round;
use rokoko::protocol::parties::verifier::verifier_round;
use rokoko::protocol::params::{decompose_witness, witness_sampler, WITNESS_CONFIG};
use rokoko::common::matrix::VerticallyAlignedMatrix;
use rokoko::common::ring_arithmetic::RingElement;
use rokoko::protocol::commitment::CommitmentWithAux;
use rokoko::protocol::sumcheck::{init_sumcheck, SumcheckContext};
use rokoko::protocol::sumchecks::builder_verifier::init_verifier;
use rokoko::protocol::sumchecks::context_verifier::VerifierSumcheckContext;

use crate::proof::RokokoHandoff;

pub struct Setup {
    config: &'static SumcheckConfig,
    crs: CRS,
    verifier_crs: VerifierCRS,
    evaluation_points: InitialEvaluationPoints,
    sumcheck_context: SumcheckContext,
    sumcheck_context_verifier: VerifierSumcheckContext,
}

impl Setup {
    pub fn crs(&self) -> &CRS {
        &self.crs
    }

    pub fn verifier_crs(&self) -> &VerifierCRS {
        &self.verifier_crs
    }
}

pub fn setup() -> Setup {
    let config = match &*CONFIG {
        Config::Sumcheck(c) => c,
        _ => panic!("expected a Sumcheck config at the chain root"),
    };
    let witness_config = &*WITNESS_CONFIG;
    let evaluation_points = sample_initial_evaluation_points(
        witness_config.height,
        witness_config.width,
        witness_config.decomposition_base_log,
        witness_config.decomposition_chunks,
    );
    let crs = CRS::gen_prover_crs(config);
    let verifier_crs = CRS::gen_verifier_crs(config);
    let sumcheck_context = init_sumcheck(&crs, config);
    let sumcheck_context_verifier = init_verifier(&verifier_crs, config);
    Setup {
        config,
        crs,
        verifier_crs,
        evaluation_points,
        sumcheck_context,
        sumcheck_context_verifier,
    }
}

pub struct ProveOutput {
    pub handoff: RokokoHandoff,
    pub prover_boundary: ProverBoundary,
}

pub fn sample() -> VerticallyAlignedMatrix<RingElement> {
    decompose_witness(&witness_sampler())
}

pub fn commit_witness(
    setup: &Setup,
    witness_decomposed: &VerticallyAlignedMatrix<RingElement>,
) -> (CommitmentWithAux, Vec<RingElement>) {
    commit(&setup.crs, setup.config, witness_decomposed)
}

pub fn prove(
    setup: &mut Setup,
    witness_decomposed: &VerticallyAlignedMatrix<RingElement>,
    commitment_with_aux: &CommitmentWithAux,
    rc_commitment: Vec<RingElement>,
    cut: NonZeroUsize,
) -> ProveOutput {
    let mut prover_boundary = None;
    let (proof, claims) = prover_round(
        &setup.crs,
        setup.config,
        commitment_with_aux,
        witness_decomposed,
        &setup.evaluation_points.inner,
        &setup.evaluation_points.outer,
        &mut setup.sumcheck_context,
        true,
        None,
        Some(BoundaryCapture { cut, slot: &mut prover_boundary }),
    );
    let claims = claims.expect("prover_round must return claims when with_claims is true");
    let prover_boundary = prover_boundary.expect("round boundary cut must populate the prover boundary");
    ProveOutput {
        handoff: RokokoHandoff { rc_commitment, proof, claims },
        prover_boundary,
    }
}

pub fn verify(setup: &mut Setup, cut: NonZeroUsize, handoff: &RokokoHandoff) -> VerifierBoundary {
    let mut verifier_boundary = None;
    verifier_round(
        &setup.verifier_crs,
        setup.config,
        &handoff.rc_commitment,
        &handoff.proof,
        &setup.evaluation_points.inner,
        &setup.evaluation_points.outer,
        &handoff.claims,
        &mut setup.sumcheck_context_verifier,
        None,
        Some(BoundaryCapture { cut, slot: &mut verifier_boundary }),
    );
    verifier_boundary.expect("round boundary cut must populate the verifier boundary")
}
