use goblin::mach::MachO;

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
}
