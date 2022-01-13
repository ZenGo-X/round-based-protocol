use generic_array::ArrayLength;
use phantom_type::PhantomType;
use typenum::Unsigned;

mod macros {
    macro_rules! Sum {
        ($single:ty $(,)?) => { $single };
        ($left:ty, $($right:ty),+ $(,)?) => {
            $crate::generic_array_ext::Sum<
                $left,
                $crate::generic_array_ext::Sum![$($right),+]
            >
        };
    }

    pub(crate) use Sum;
}

pub(crate) use macros::Sum;

#[derive(Copy, Clone, Default)]
pub struct Sum<U1: Unsigned, U2: Unsigned> {
    _ph: PhantomType<(U1, U2)>,
}

#[doc(hidden)]
pub struct GenericArrayImplSum<T, U1: ArrayLength<T>, U2: ArrayLength<T>> {
    _left: U1::ArrayType,
    _right: U2::ArrayType,
    _ph: PhantomType<T>,
}

impl<U1, U2> Unsigned for Sum<U1, U2>
where
    U1: Unsigned,
    U2: Unsigned,
{
    const U8: u8 = U1::U8 + U2::U8;
    const U16: u16 = U1::U16 + U2::U16;
    const U32: u32 = U1::U32 + U2::U32;
    const U64: u64 = U1::U64 + U2::U64;
    const USIZE: usize = U1::USIZE + U2::USIZE;
    const I8: i8 = U1::I8 + U2::I8;
    const I16: i16 = U1::I16 + U2::I16;
    const I32: i32 = U1::I32 + U2::I32;
    const I64: i64 = U1::I64 + U2::I64;
    const ISIZE: isize = U1::ISIZE + U2::ISIZE;

    fn to_u8() -> u8 {
        Self::U8
    }
    fn to_u16() -> u16 {
        Self::U16
    }
    fn to_u32() -> u32 {
        Self::U32
    }
    fn to_u64() -> u64 {
        Self::U64
    }
    fn to_usize() -> usize {
        Self::USIZE
    }
    fn to_i8() -> i8 {
        Self::I8
    }
    fn to_i16() -> i16 {
        Self::I16
    }
    fn to_i32() -> i32 {
        Self::I32
    }
    fn to_i64() -> i64 {
        Self::I64
    }
    fn to_isize() -> isize {
        Self::ISIZE
    }
}

unsafe impl<T, U1, U2> ArrayLength<T> for Sum<U1, U2>
where
    U1: ArrayLength<T>,
    U2: ArrayLength<T>,
{
    #[doc(hidden)]
    type ArrayType = GenericArrayImplSum<T, U1, U2>;
}

#[cfg(test)]
mod tests {
    use generic_array::typenum::*;
    use generic_array::{ArrayLength, GenericArray};
    use rand::rngs::OsRng;
    use rand::RngCore;

    use super::Sum;

    #[test]
    fn check_that_arrays_behave_the_same() {
        check_that_arrays_behave_the_same_for_fixed_size::<U0, 0>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U0, U0], 0>();

        check_that_arrays_behave_the_same_for_fixed_size::<U1, 1>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U1, U0], 1>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U0, U1], 1>();

        check_that_arrays_behave_the_same_for_fixed_size::<U10, 10>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U5, U5], 10>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U3, U7], 10>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U9, U1], 10>();

        check_that_arrays_behave_the_same_for_fixed_size::<U32, 32>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U16, U16], 32>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U10, U22], 32>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U25, U7], 32>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U16, U10, U6], 32>();

        check_that_arrays_behave_the_same_for_fixed_size::<U128, 128>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U64, U64], 128>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U13, U115], 128>();
        check_that_arrays_behave_the_same_for_fixed_size::<Sum![U4, U9, U98, U17], 128>();

        check_that_arrays_behave_the_same_for_fixed_size::<U4096, 4096>();
        check_that_arrays_behave_the_same_for_fixed_size::<
            Sum![U1000, U1000, U1000, U1023, U73],
            4096,
        >();
    }

    fn check_that_arrays_behave_the_same_for_fixed_size<
        Size: ArrayLength<u8>,
        const SIZE: usize,
    >() {
        let mut arr1 = [0u8; SIZE];
        let mut arr2 = GenericArray::<u8, Size>::default();

        assert_eq!(arr1.len(), arr2.len());

        OsRng.fill_bytes(&mut arr1);
        arr2.copy_from_slice(&arr1);

        assert_eq!(arr1, &*arr2);
    }
}
