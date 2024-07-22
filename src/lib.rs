#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]
#![warn(clippy::semicolon_if_nothing_returned)]

use acvm::{
    acir::circuit::{Circuit, Opcode},
    FieldElement,
};
use noirc_artifacts::program::ProgramArtifact;
use noirc_driver::CompiledProgram;
use std::path::{Path, PathBuf};

pub mod bridge;
mod concrete_cfg;
mod serializer;

pub use concrete_cfg::{from_fe, Curve, CurveAcir, Fr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FilesystemError {
    #[error("Error: {} is not a valid path\nRun either `nargo compile` to generate missing build artifacts or `nargo prove` to construct a proof", .0.display())]
    PathNotValid(PathBuf),
    #[error("Error: could not deserialize build program: {0}")]
    ProgramSerializationError(String),
}

pub fn read_program_from_file<P: AsRef<Path>>(
    circuit_path: P,
) -> Result<CompiledProgram, FilesystemError> {
    let file_path = circuit_path.as_ref().with_extension("json");
    let input_string =
        std::fs::read(&file_path).map_err(|_| FilesystemError::PathNotValid(file_path))?;
    let program: ProgramArtifact = serde_json::from_slice(&input_string)
        .map_err(|err| FilesystemError::ProgramSerializationError(err.to_string()))?;
    let compiled_program: CompiledProgram = program.into();
    Ok(compiled_program)
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
        let circuit: Circuit<FieldElement> = compiled_prg.program.functions[0].clone();

        // instantiate acvm to compute a witness
        let mut acvm = ACVM::new(
            &StubbedBlackBoxSolver,
            &circuit.opcodes,
            WitnessMap::new(),
            &[],
            &[],
        );

        // provide public input parameters
        acvm.overwrite_witness(Witness(0), FieldElement::from(2 as usize));
        acvm.overwrite_witness(Witness(1), FieldElement::from(2 as usize));

        // provide private input parameters
        acvm.overwrite_witness(Witness(2), FieldElement::from(2 as usize));
        acvm.overwrite_witness(Witness(3), FieldElement::from(2 as usize));
        acvm.solve();
        let witness_map = acvm.finalize();

        // generate constraints using witness values that have been generated
        let circuit_acir = CurveAcir::from((&circuit, witness_map));
        let res = circuit_acir.clone().generate_constraints(cs.clone());

        assert!(res.is_ok())
    }
}
