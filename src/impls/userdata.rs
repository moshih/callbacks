use crate::generic::user::UserData;
use ark_bls12_381::Fr;
use ark_bn254::Fr as F;
use ark_ff::ToConstraintField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBytesGadget;
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint128::UInt128;
use ark_r1cs_std::uint16::UInt16;
use ark_r1cs_std::uint32::UInt32;
use ark_r1cs_std::uint64::UInt64;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::SynthesisError;

macro_rules! impl_userdata {
    ( $x:ty, $f:ty, $y:ty ) => {
        impl UserData<$f> for $x {
            type UserDataVar = $y;

            fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<$f>> {
                let mut buf: Vec<$f> = Vec::new();
                buf.extend_from_slice(&self.to_field_elements().unwrap());
                buf
            }

            fn serialize_in_zk(
                user_var: Self::UserDataVar,
            ) -> Result<Vec<crate::generic::object::SerVar<$f>>, SynthesisError> {
                let mut buf: Vec<FpVar<$f>> = Vec::new();
                buf.extend_from_slice(&user_var.to_constraint_field()?);
                Ok(buf)
            }
        }
    };
}

impl_userdata!(bool, F, Boolean<F>);
impl_userdata!(F, F, FpVar<F>);

impl_userdata!(bool, Fr, Boolean<Fr>);
impl_userdata!(Fr, Fr, FpVar<Fr>);

impl UserData<F> for u8 {
    type UserDataVar = UInt8<F>;

    fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<F>> {
        let mut buf: Vec<F> = Vec::new();
        buf.extend_from_slice(&self.to_le_bytes().to_field_elements().unwrap());
        buf
    }

    fn serialize_in_zk(
        user_var: Self::UserDataVar,
    ) -> Result<Vec<crate::generic::object::SerVar<F>>, SynthesisError> {
        let mut buf: Vec<FpVar<F>> = Vec::new();
        let v = [user_var; 1];
        let bytevec = &v.to_bytes_le()?;
        let ser_vec = bytevec.to_constraint_field()?;
        buf.extend_from_slice(&ser_vec);
        Ok(buf)
    }
}

impl UserData<Fr> for u8 {
    type UserDataVar = UInt8<Fr>;

    fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<Fr>> {
        let mut buf: Vec<Fr> = Vec::new();
        buf.extend_from_slice(&self.to_le_bytes().to_field_elements().unwrap());
        buf
    }

    fn serialize_in_zk(
        user_var: Self::UserDataVar,
    ) -> Result<Vec<crate::generic::object::SerVar<Fr>>, SynthesisError> {
        let mut buf: Vec<FpVar<Fr>> = Vec::new();
        let v = [user_var; 1];
        let bytevec = &v.to_bytes_le()?;
        let ser_vec = bytevec.to_constraint_field()?;
        buf.extend_from_slice(&ser_vec);
        Ok(buf)
    }
}

macro_rules! impl_complex_userdata {
    ( $x:ty, $f:ty, $y:ty ) => {
        impl UserData<$f> for $x {
            type UserDataVar = $y;

            fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<$f>> {
                let mut buf: Vec<$f> = Vec::new();
                buf.extend_from_slice(&self.to_le_bytes().to_field_elements().unwrap());
                buf
            }

            fn serialize_in_zk(
                user_var: Self::UserDataVar,
            ) -> Result<Vec<crate::generic::object::SerVar<$f>>, SynthesisError> {
                let mut buf: Vec<FpVar<$f>> = Vec::new();
                let boolvec = &user_var.to_bytes_le();
                let ser_vec = boolvec
                    .into_iter()
                    .flat_map(|x| x.to_constraint_field())
                    .flatten()
                    .collect::<Vec<FpVar<$f>>>();
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

impl_complex_userdata!(u16, Fr, UInt16<Fr>);
impl_complex_userdata!(u32, Fr, UInt32<Fr>);
impl_complex_userdata!(u64, Fr, UInt64<Fr>);
impl_complex_userdata!(u128, Fr, UInt128<Fr>);

// TODO: Implement complex userdata for Vec<T>, [T; N]
