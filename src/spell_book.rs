use anyhow::{bail, Result};
use std::collections::HashMap;
use crate::spells::*;

pub struct SpellBook {
    spells: Vec<Box<dyn Spell>>,
}

impl SpellBook {
    pub fn new() -> Self {
        let spells: Vec<Box<dyn Spell>> = vec![
            Box::new(AccioTgt),
            Box::new(AccioService),
            Box::new(RoastingFeast),
            Box::new(PreauthFeast),
            Box::new(ElderWand),
            Box::new(DarkMark),
            Box::new(PhilosophersStone),
            Box::new(Portkey),
            Box::new(Obliviate),
            Box::new(Polyjuice),
            Box::new(Confundus),
            Box::new(MaraudersMap),
            Box::new(Reaping),
            Box::new(Crucio),
            Box::new(SortingHat),
            Box::new(Legilimens),
            Box::new(Reparo),
            Box::new(Alohomora),
            Box::new(Transfigure),
            Box::new(Fidelius),
            Box::new(Imperius),
            Box::new(Muggle),
            Box::new(ConvertMuggle),
            Box::new(Whomst),
            Box::new(SessionMap),
            Box::new(Pillage),
            Box::new(Census),
            Box::new(Manifest),
        ];
        Self { spells }
    }

    pub fn cast(&self, name: &str, args: &HashMap<String, String>) -> Result<()> {
        let normalized = name.replace('_', "-").to_ascii_lowercase();
        for spell in &self.spells {
            if spell.incantation() == normalized {
                return spell.cast(args);
            }
        }
        bail!("Unknown spell '{}'. Try 'hagrid help'.", name)
    }

    pub fn print_help(&self) {
        println!("  Available spells:\n");
        let mut col = crate::dungeon::display_charm::GrimoireTable::new(vec!["Spell", "Description"]);
        for spell in &self.spells {
            col.add_row(vec![spell.incantation().to_owned(), spell.grimoire().to_owned()]);
        }
        col.print();
    }
}
