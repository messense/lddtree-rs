use goblin::{
    mach::{Mach, MachO},
    Object,
};

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
            Object::Mach(mach) => match mach {
                Mach::Fat(fat) => {
                    for macho in fat {
                        if let Ok(goblin::mach::SingleArch::MachO(macho)) = macho {
                            if self.compatible(&Object::Mach(Mach::Binary(macho))) {
                                return true;
                            }
                        }
                    }
                    false
                }
                Mach::Binary(macho) => {
                    if self.is_64 != macho.is_64 {
                        return false;
                    }
                    if self.little_endian != macho.little_endian {
                        return false;
                    }
                    if self.header.cputype != macho.header.cputype {
                        return false;
                    }
                    true
                }
            },
            _ => false,
        }
    }
}
