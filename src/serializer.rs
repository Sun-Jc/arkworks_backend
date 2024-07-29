use crate::bridge::{AcirArithGate, AcirCircuit};
use crate::concrete_cfg::CurveAcir;
use crate::sonobe_bridge::AcirCircuitSonobe;
use acvm::acir::acir_field::GenericFieldElement;
use acvm::{
    acir::{
        circuit::{Circuit, Opcode},
        native_types::{Expression, Witness, WitnessMap},
    },
    FieldElement,
};
use ark_ff::PrimeField;
use std::collections::HashMap;
use std::{collections::BTreeMap, convert::TryInto};

impl From<&Circuit<FieldElement>> for CurveAcir {
    fn from(circuit: &Circuit<FieldElement>) -> CurveAcir {
        CurveAcir::from((circuit, WitnessMap::new()))
    }
}
impl<'a, F: PrimeField>
    From<(
        &Circuit<GenericFieldElement<F>>,
        WitnessMap<GenericFieldElement<F>>,
    )> for AcirCircuitSonobe<'a, F>
{
    fn from(
        circ_val: (
            &Circuit<GenericFieldElement<F>>,
            WitnessMap<GenericFieldElement<F>>,
        ),
    ) -> AcirCircuitSonobe<'a, F> {
        let circuit = AcirCircuit::from(circ_val);
        AcirCircuitSonobe {
            gates: circuit.gates,
            public_inputs: circuit.public_inputs,
            values: circuit.values,
            already_assigned_witnesses: HashMap::new(),
        }
    }
}

impl<F: PrimeField>
    From<(
        &Circuit<GenericFieldElement<F>>,
        WitnessMap<GenericFieldElement<F>>,
    )> for AcirCircuit<F>
{
    fn from(
        circ_val: (
            &Circuit<GenericFieldElement<F>>,
            WitnessMap<GenericFieldElement<F>>,
        ),
    ) -> AcirCircuit<F> {
        // Currently non-arithmetic gates are not supported
        // so we extract all of the arithmetic gates only
        let (circuit, witness_map) = circ_val;

        let public_inputs = circuit.public_inputs();
        let arith_gates: Vec<_> = circuit
            .opcodes
            .iter()
            .filter_map(|opcode| {
                if let Opcode::AssertZero(code) = opcode {
                    Some(AcirArithGate::<F>::from(code.clone()))
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
                    .map_or(F::zero(), |field| field.into_repr());

                (witness, value)
            })
            .collect();

        AcirCircuit {
            gates: arith_gates,
            values,
            // num_variables,
            public_inputs,
        }
    }
}

impl<F: PrimeField> From<Expression<GenericFieldElement<F>>> for AcirArithGate<F> {
    fn from(arith_gate: Expression<GenericFieldElement<F>>) -> AcirArithGate<F> {
        let converted_mul_terms: Vec<_> = arith_gate
            .mul_terms
            .into_iter()
            .map(|(coeff, l_var, r_var)| (coeff.into_repr(), l_var, r_var))
            .collect();

        let converted_linear_combinations: Vec<_> = arith_gate
            .linear_combinations
            .into_iter()
            .map(|(coeff, var)| (coeff.into_repr(), var))
            .collect();

        AcirArithGate {
            mul_terms: converted_mul_terms,
            add_terms: converted_linear_combinations,
            constant_term: arith_gate.q_c.into_repr(),
        }
    }
}
