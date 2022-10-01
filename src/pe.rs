use goblin::{pe::PE, Object};

use crate::InspectDylib;

impl InspectDylib for PE<'_> {
    fn rpaths(&self) -> &[&str] {
        &[]
    }

    fn libraries(&self) -> Vec<&str> {
        self.libraries.clone()
    }

    fn interpreter(&self) -> Option<&str> {
        None
    }

    fn compatible(&self, other: &Object) -> bool {
        match other {
            Object::PE(pe) => {
                if self.is_64 != pe.is_64 {
                    return false;
                }
                if self.header.coff_header.machine != pe.header.coff_header.machine {
                    return false;
                }
                true
            }
            _ => false,
        }
    }
}
