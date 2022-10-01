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
            Object::PE(_) => true,
            _ => false,
        }
    }
}
