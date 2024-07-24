use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::vm_core::VirtualMachine;

pub trait CairoType: Sized {
    fn from_memory(vm: &VirtualMachine, address: Relocatable) -> Result<Self, MemoryError>;
    fn to_memory(&self, vm: &mut VirtualMachine, address: Relocatable) -> Result<(), MemoryError>;

    fn n_fields() -> usize;
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use cairo_type_derive::{CairoType, FieldOffsetGetters};
    use cairo_vm::Felt252;

    use super::*;

    #[derive(CairoType, FieldOffsetGetters)]
    struct MyType {
        pub a: Felt252,
        pub b: Felt252,
        pub c: Felt252,
    }

    #[derive(FieldOffsetGetters)]
    struct MyNestedType {
        #[allow(unused)]
        pub x: Felt252,
        #[allow(unused)]
        pub y: MyType,
        #[allow(unused)]
        pub z: Felt252,
    }

    #[test]
    fn write_cairo_type() {
        let mut vm = VirtualMachine::new(false);
        let base_address = vm.add_memory_segment();

        let m = MyType { a: Felt252::ONE, b: Felt252::TWO, c: Felt252::THREE };
        m.to_memory(&mut vm, base_address).unwrap();

        let values = vm.get_integer_range(base_address, 3).unwrap();
        assert_eq!(values[0], Cow::Borrowed(&m.a));
        assert_eq!(values[1], Cow::Borrowed(&m.b));
        assert_eq!(values[2], Cow::Borrowed(&m.c));
    }

    #[test]
    fn read_cairo_type() {
        let mut vm = VirtualMachine::new(false);

        // Check that reading from a non-existing segment fails
        assert!(MyType::from_memory(&mut vm, Relocatable::from((0, 0))).is_err());

        // Check that reading an existing segment without data fails
        let base_address = vm.add_memory_segment();
        assert!(MyType::from_memory(&mut vm, base_address).is_err());

        // Write the data and read it
        vm.insert_value(base_address, Felt252::ONE).unwrap();
        vm.insert_value((base_address + 1usize).unwrap(), Felt252::TWO).unwrap();
        vm.insert_value((base_address + 2usize).unwrap(), Felt252::THREE).unwrap();

        let m = MyType::from_memory(&vm, base_address).unwrap();
        assert_eq!(m.a, Felt252::ONE);
        assert_eq!(m.b, Felt252::TWO);
        assert_eq!(m.c, Felt252::THREE);
    }

    #[test]
    fn n_fields() {
        assert_eq!(MyType::n_fields(), 3);
    }

    #[test]
    fn field_offsets() {
        assert_eq!(MyType::a_offset(), 0);
        assert_eq!(MyType::b_offset(), 1);
        assert_eq!(MyType::c_offset(), 2);

        assert_eq!(MyType::cairo_size(), 3);

        assert_eq!(MyNestedType::x_offset(), 0);
        assert_eq!(MyNestedType::y_offset(), 1);
        assert_eq!(MyNestedType::z_offset(), 4);

        assert_eq!(MyNestedType::cairo_size(), 5);
    }
}
