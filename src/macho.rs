use goblin::{mach::MachO, Object};

use crate::InspectDylib;

impl InspectDylib for MachO<'_> {
    fn rpaths(&self) -> &[&str] {
        &self.rpaths
    }

    fn libraries(&self) -> Vec<&str> {
        // goblin always add `self` or dylib id as a needed library, so we need to remove it, see
        // https://github.com/m4b/goblin/blob/6fdaffdc411bacd5dd7095dc93cec66302ca2575/src/mach/mod.rs#L174
        // https://github.com/m4b/goblin/blob/6fdaffdc411bacd5dd7095dc93cec66302ca2575/src/mach/mod.rs#L231-L235
        self.libs[1..].to_vec()
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
