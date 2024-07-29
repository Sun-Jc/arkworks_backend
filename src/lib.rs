#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]
#![warn(clippy::semicolon_if_nothing_returned)]

use acvm::{
    acir::{
        acir_field::GenericFieldElement,
        circuit::{Circuit, Opcode, Program},
    },
    FieldElement,
};
use ark_ff::PrimeField;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub mod bridge;
mod concrete_cfg;
mod serializer;
pub mod sonobe_bridge;
use fm::FileId;
use serde::{Deserialize, Serialize};

pub use concrete_cfg::{from_fe, Curve, CurveAcir, Fr};
use noirc_abi::Abi;
use noirc_driver::DebugFile;
use noirc_errors::debug_info::ProgramDebugInfo;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FilesystemError {
    #[error("Error: {} is not a valid path\nRun either `nargo compile` to generate missing build artifacts or `nargo prove` to construct a proof", .0.display())]
    PathNotValid(PathBuf),
    #[error("Error: could not deserialize build program: {0}")]
    ProgramSerializationError(String),
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProgramArtifactGeneric<F: PrimeField> {
    pub noir_version: String,

    /// Hash of the [`Program`][noirc_frontend::monomorphization::ast::Program] from which this [`ProgramArtifact`]
    /// was compiled.
    ///
    /// Used to short-circuit compilation in the case of the source code not changing since the last compilation.
    pub hash: u64,
    pub abi: Abi,
    #[serde(
        serialize_with = "Program::serialize_program_base64",
        deserialize_with = "Program::deserialize_program_base64"
    )]
    pub bytecode: Program<GenericFieldElement<F>>,
    #[serde(
        serialize_with = "ProgramDebugInfo::serialize_compressed_base64_json",
        deserialize_with = "ProgramDebugInfo::deserialize_compressed_base64_json"
    )]
    pub debug_symbols: ProgramDebugInfo,
    /// Map of file Id to the source code so locations in debug info can be mapped to source code they point to.
    pub file_map: BTreeMap<FileId, DebugFile>,
    pub names: Vec<String>,
}

pub fn read_program_from_file<F: PrimeField, P: AsRef<Path>>(
    circuit_path: P,
) -> Result<Program<GenericFieldElement<F>>, FilesystemError> {
    let file_path = circuit_path.as_ref().with_extension("json");
    let input_string =
        std::fs::read(&file_path).map_err(|_| FilesystemError::PathNotValid(file_path))?;
    let program: ProgramArtifactGeneric<F> = serde_json::from_slice(&input_string)
        .map_err(|err| FilesystemError::ProgramSerializationError(err.to_string()))?;
    Ok(program.bytecode)
}

pub fn compute_num_opcodes(acir: &Circuit<FieldElement>) -> u32 {
    let mut num_opcodes = acir.opcodes.len();

    for opcode in acir.opcodes.iter() {
        match opcode {
            Opcode::AssertZero(arith) => {
                // Each multiplication term adds an extra constraint
                // plus one for the linear combination gate.
                num_opcodes += arith.num_mul_terms() + 1;
            }
            Opcode::Directive(_) => (),
            _ => unreachable!(
                "currently we do not support non-arithmetic opcodes {:?}",
                opcode
            ),
        }
    }

    num_opcodes as u32
}

#[cfg(test)]
mod test {
    use acvm::acir::acir_field::GenericFieldElement;
    use acvm::blackbox_solver::StubbedBlackBoxSolver;
    use acvm::pwg::ACVM;
    use acvm::AcirField;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use std::collections::BTreeSet;
    use std::env;

    use super::*;
    use acvm::acir::circuit::{ExpressionWidth, Opcode, PublicInputs};
    use acvm::acir::native_types::{Expression, Witness, WitnessMap};
    use acvm::FieldElement;

    #[test]
    fn simple_equal() {
        let a = Witness(1);
        let b = Witness(2);

        // assert a == b
        let arith = Expression {
            mul_terms: vec![],
            linear_combinations: vec![(FieldElement::one(), a), (-FieldElement::one(), b)],
            q_c: FieldElement::zero(),
        };
        let opcode = Opcode::AssertZero(arith);
        let _circ = Circuit {
            expression_width: ExpressionWidth::Unbounded,
            recursive: false,
            current_witness_index: 2,
            opcodes: vec![opcode],
            public_parameters: PublicInputs(BTreeSet::from([Witness(1)])),
            return_values: PublicInputs(BTreeSet::new()),
            private_parameters: BTreeSet::new(),
            assert_messages: Vec::new(),
        };
        let a_val = FieldElement::from(6_i128);
        let b_val = FieldElement::from(6_i128);
        let _values = vec![&a_val, &b_val];
    }

    #[test]
    fn test_simple_circuit() {
        let cs = ConstraintSystem::new_ref();
        let cur_path = env::current_dir().unwrap();
        let circuit_path = format!("{}/src/artifacts/test_circuit", cur_path.to_str().unwrap());
        let compiled_prg = read_program_from_file(circuit_path).unwrap();
        type F = GenericFieldElement<Fr>;
        let circuit: Circuit<F> = compiled_prg.functions[0].clone();

        // instantiate acvm to compute a witness
        let mut acvm = ACVM::new(
            &StubbedBlackBoxSolver,
            &circuit.opcodes,
            WitnessMap::new(),
            &[],
            &[],
        );

        // provide public input parameters
        acvm.overwrite_witness(Witness(0), F::from(2 as usize));
        acvm.overwrite_witness(Witness(1), F::from(2 as usize));

        // provide private input parameters
        acvm.overwrite_witness(Witness(2), F::from(2 as usize));
        acvm.overwrite_witness(Witness(3), F::from(2 as usize));
        acvm.solve();
        let witness_map = acvm.finalize();

        // generate constraints using witness values that have been generated
        let circuit_acir = CurveAcir::from((&circuit, witness_map));
        let res = circuit_acir.clone().generate_constraints(cs.clone());

        assert!(res.is_ok())
    }
}
