use crate::generic::user::UserData;
use ark_bls12_381::Fr as F;
use ark_ff::ToConstraintField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint128::UInt128;
use ark_r1cs_std::uint16::UInt16;
use ark_r1cs_std::uint32::UInt32;
use ark_r1cs_std::uint64::UInt64;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::ToBitsGadget;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::r1cs::SynthesisError;

macro_rules! impl_userdata {
    ( $x:ty, $f:ty, $y:ty ) => {
        impl UserData for $x {
            type F = $f;
            type UserDataVar = $y;

            fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<Self::F>> {
                let mut buf: Vec<F> = Vec::new();
                buf.extend_from_slice(&self.to_field_elements().unwrap());
                buf
            }

            fn serialize_in_zk(
                user_var: Self::UserDataVar,
            ) -> Result<Vec<crate::generic::object::SerVar<Self::F>>, SynthesisError> {
                let mut buf: Vec<FpVar<F>> = Vec::new();
                buf.extend_from_slice(&user_var.to_constraint_field()?);
                Ok(buf)
            }
        }
    };
}

impl_userdata!(bool, F, Boolean<F>);
impl_userdata!(F, F, FpVar<F>);

impl UserData for u8 {
    type F = F;
    type UserDataVar = UInt8<F>;

    fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<Self::F>> {
        let mut buf: Vec<F> = Vec::new();
        buf.extend_from_slice(&self.to_le_bytes().as_slice().to_field_elements().unwrap());
        buf
    }

    fn serialize_in_zk(
        user_var: Self::UserDataVar,
    ) -> Result<Vec<crate::generic::object::SerVar<Self::F>>, SynthesisError> {
        let mut buf: Vec<FpVar<F>> = Vec::new();
        let boolvec = &user_var.to_bits_le()?;
        let ser_vec = boolvec
            .iter()
            .flat_map(|x| x.to_constraint_field())
            .flatten()
            .collect::<Vec<FpVar<F>>>();
        buf.extend_from_slice(&ser_vec);
        Ok(buf)
    }
}

macro_rules! impl_complex_userdata {
    ( $x:ty, $f:ty, $y:ty ) => {
        impl UserData for $x {
            type F = $f;
            type UserDataVar = $y;

            fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<Self::F>> {
                let mut buf: Vec<F> = Vec::new();
                buf.extend_from_slice(&self.to_le_bytes().as_slice().to_field_elements().unwrap());
                buf
            }

            fn serialize_in_zk(
                user_var: Self::UserDataVar,
            ) -> Result<Vec<crate::generic::object::SerVar<Self::F>>, SynthesisError> {
                let mut buf: Vec<FpVar<F>> = Vec::new();
                let boolvec = &user_var.to_bits_le();
                let ser_vec = boolvec
                    .into_iter()
                    .flat_map(|x| x.to_constraint_field())
                    .flatten()
                    .collect::<Vec<FpVar<F>>>();
                buf.extend_from_slice(&ser_vec);
                Ok(buf)
            }
        }
    };
}

impl_complex_userdata!(u16, F, UInt16<F>);
impl_complex_userdata!(u32, F, UInt32<F>);
impl_complex_userdata!(u64, F, UInt64<F>);
impl_complex_userdata!(u128, F, UInt128<F>);
