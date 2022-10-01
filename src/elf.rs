use goblin::{
    elf::{
        header::{EI_OSABI, ELFOSABI_GNU, ELFOSABI_NONE},
        Elf,
    },
    Object,
};

use crate::InspectDylib;

impl InspectDylib for Elf<'_> {
    fn rpaths(&self) -> &[&str] {
        if !self.runpaths.is_empty() {
            &self.runpaths
        } else {
            &self.rpaths
        }
    }

    fn libraries(&self) -> &[&str] {
        &self.libraries
    }

    fn interpreter(&self) -> Option<&str> {
        self.interpreter.clone()
    }

    /// See if two ELFs are compatible
    ///
    /// This compares the aspects of the ELF to see if they're compatible:
    /// bit size, endianness, machine type, and operating system.
    fn compatible(&self, other: &Object) -> bool {
        match other {
            Object::Elf(other) => {
                if self.is_64 != other.is_64 {
                    return false;
                }
                if self.little_endian != other.little_endian {
                    return false;
                }
                if self.header.e_machine != other.header.e_machine {
                    return false;
                }
                let compatible_osabis = &[
                    ELFOSABI_NONE, // ELFOSABI_NONE / ELFOSABI_SYSV
                    ELFOSABI_GNU,  // ELFOSABI_GNU / ELFOSABI_LINUX
                ];
                let osabi1 = self.header.e_ident[EI_OSABI];
                let osabi2 = other.header.e_ident[EI_OSABI];
                if osabi1 != osabi2
                    && !compatible_osabis.contains(&osabi1)
                    && !compatible_osabis.contains(&osabi2)
                {
                    return false;
                }
                true
            }
            _ => false,
        }
    }
}
