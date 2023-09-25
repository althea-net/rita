use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Debug)]
pub enum RitaDBMigrationError {
    MiscStringError(String),
}

impl Display for RitaDBMigrationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            RitaDBMigrationError::MiscStringError(a) => write!(f, "{a}",),
        }
    }
}

impl Error for RitaDBMigrationError {}
