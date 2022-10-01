use goblin::{mach::MachO, Object};

use crate::InspectDylib;

impl InspectDylib for MachO<'_> {
    fn rpaths(&self) -> &[&str] {
        &self.rpaths
    }

    fn libraries(&self) -> &[&str] {
        &self.libs
    }

    fn interpreter(&self) -> Option<&str> {
        None
    }

    fn compatible(&self, other: &Object) -> bool {
        match other {
            Object::Mach(_) => true,
            _ => false,
        }
    }
}
