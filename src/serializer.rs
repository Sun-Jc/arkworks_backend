use crate::concrete_cfg::{from_fe, CurveAcir, CurveAcirArithGate};
use acvm::AcirField;
use acvm::{
    acir::{
        circuit::{Circuit, Opcode},
        native_types::{Expression, Witness, WitnessMap},
    },
    FieldElement,
};
use std::{collections::BTreeMap, convert::TryInto};

impl From<&Circuit<FieldElement>> for CurveAcir {
    fn from(circuit: &Circuit<FieldElement>) -> CurveAcir {
        CurveAcir::from((circuit, WitnessMap::new()))
    }
}

impl From<(&Circuit<FieldElement>, WitnessMap<FieldElement>)> for CurveAcir {
    fn from(circ_val: (&Circuit<FieldElement>, WitnessMap<FieldElement>)) -> CurveAcir {
        // Currently non-arithmetic gates are not supported
        // so we extract all of the arithmetic gates only
        let (circuit, witness_map) = circ_val;

        let public_inputs = circuit.public_inputs();
        let arith_gates: Vec<_> = circuit
            .opcodes
            .iter()
            .filter_map(|opcode| {
                if let Opcode::AssertZero(code) = opcode {
                    Some(CurveAcirArithGate::from(code.clone()))
                } else {
                    None
                }
            })
            .collect();

        let num_variables: usize = circuit.num_vars().try_into().unwrap();

        let values: BTreeMap<Witness, _> = (0..num_variables)
            .map(|witness_index| {
                // Get the value if it exists. If i does not, then we fill it with the zero value
                let witness = Witness(witness_index as u32);
                let value = witness_map
                    .get(&witness)
                    .map_or(FieldElement::zero(), |field| *field);

                (witness, from_fe(value))
            })
            .collect();

        CurveAcir {
            gates: arith_gates,
            values,
            // num_variables,
            public_inputs,
        }
    }
}

impl From<Expression<FieldElement>> for CurveAcirArithGate {
    fn from(arith_gate: Expression<FieldElement>) -> CurveAcirArithGate {
        let converted_mul_terms: Vec<_> = arith_gate
            .mul_terms
            .into_iter()
            .map(|(coeff, l_var, r_var)| (from_fe(coeff), l_var, r_var))
            .collect();

        let converted_linear_combinations: Vec<_> = arith_gate
            .linear_combinations
            .into_iter()
            .map(|(coeff, var)| (from_fe(coeff), var))
            .collect();

        CurveAcirArithGate {
            mul_terms: converted_mul_terms,
            add_terms: converted_linear_combinations,
            constant_term: from_fe(arith_gate.q_c),
        }
    }
}
