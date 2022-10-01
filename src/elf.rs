use goblin::elf::Elf;

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
}
