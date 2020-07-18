//! There once was a dream of simplifying the way we handled contact info within Rita, instead of having a struct with two invalid strings
//! and extraneous data in our configs (ExitRegDetails) we would have a single enum with a definitive set of possibilities. Well it turns out
//! we need to convert said enum between different types left and right. Both to migrate from the old storage, to handle the fact that TOML refuses
//! to serialize enums with struct members. This file is all boilerplate conversion code for pretty small storage formats.

use crate::ExitRegistrationDetails;
use lettre::EmailAddress;
use phonenumber::PhoneNumber;

/// Struct for submitting contact details to exits
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ContactDetails {
    pub phone: Option<String>,
    pub email: Option<String>,
}

impl From<ContactType> for ContactDetails {
    fn from(val: ContactType) -> Self {
        match val {
            ContactType::Phone { number } => ContactDetails {
                phone: Some(number.to_string()),
                email: None,
            },
            ContactType::Email { email } => ContactDetails {
                phone: None,
                email: Some(email.to_string()),
            },
            ContactType::Both { email, number } => ContactDetails {
                phone: Some(number.to_string()),
                email: Some(email.to_string()),
            },
            ContactType::Bad {
                invalid_email,
                invalid_number,
            } => ContactDetails {
                phone: invalid_number,
                email: invalid_email,
            },
        }
    }
}

impl ContactType {
    pub fn convert(val: ContactDetails) -> Option<Self> {
        let same = ExitRegistrationDetails {
            phone: val.phone,
            email: val.email,
            phone_code: None,
            email_code: None,
        };
        match ContactStorage::convert(same) {
            Some(val) => Some(val.into()),
            None => None,
        }
    }
}

impl From<Option<ContactType>> for ContactDetails {
    fn from(val: Option<ContactType>) -> Self {
        match val {
            Some(val) => val.into(),
            None => ContactDetails {
                phone: None,
                email: None,
            },
        }
    }
}

/// This enum is used to represent the fact that while we may not have a phone
/// number and may not have an Email we are required to have at least one to
/// facilitate exit registration.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum ContactType {
    Phone {
        number: PhoneNumber,
    },
    Email {
        email: EmailAddress,
    },
    Both {
        number: PhoneNumber,
        email: EmailAddress,
    },
    /// During migration we may encounter invalid values we don't want
    /// to lose this info so we store it in this variant.
    Bad {
        invalid_number: Option<String>,
        invalid_email: Option<String>,
    },
}

/// TOML compatible storage for contact type, all work done on this
/// should be converted to ContactType, so don't make the fields public
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ContactStorage {
    number: Option<PhoneNumber>,
    email: Option<EmailAddress>,
    invalid_number: Option<String>,
    invalid_email: Option<String>,
}

impl From<ContactType> for ContactStorage {
    fn from(val: ContactType) -> Self {
        match val {
            ContactType::Both { number, email } => ContactStorage {
                number: Some(number),
                email: Some(email),
                invalid_number: None,
                invalid_email: None,
            },
            ContactType::Phone { number } => ContactStorage {
                number: Some(number),
                email: None,
                invalid_email: None,
                invalid_number: None,
            },
            ContactType::Email { email } => ContactStorage {
                number: None,
                email: Some(email),
                invalid_email: None,
                invalid_number: None,
            },
            ContactType::Bad {
                invalid_email: val_e,
                invalid_number: val_p,
            } => ContactStorage {
                number: None,
                email: None,
                invalid_email: val_e,
                invalid_number: val_p,
            },
        }
    }
}

impl From<ContactStorage> for ContactType {
    fn from(storage: ContactStorage) -> Self {
        match storage {
            ContactStorage {
                number: Some(phone),
                email: Some(email),
                invalid_email: _,
                invalid_number: _,
            } => ContactType::Both {
                number: phone,
                email,
            },
            ContactStorage {
                number: Some(phone),
                email: None,
                invalid_email: _,
                invalid_number: _,
            } => ContactType::Phone { number: phone },
            ContactStorage {
                number: None,
                email: Some(email),
                invalid_email: _,
                invalid_number: _,
            } => ContactType::Email { email },
            ContactStorage {
                number: None,
                email: None,
                invalid_email: Some(val),
                invalid_number: None,
            } => ContactType::Bad {
                invalid_email: Some(val),
                invalid_number: None,
            },
            ContactStorage {
                number: None,
                email: None,
                invalid_email: None,
                invalid_number: Some(val),
            } => ContactType::Bad {
                invalid_email: None,
                invalid_number: Some(val),
            },
            ContactStorage {
                number: None,
                email: None,
                invalid_email: Some(val_e),
                invalid_number: Some(val_p),
            } => ContactType::Bad {
                invalid_email: Some(val_e),
                invalid_number: Some(val_p),
            },
            ContactStorage {
                number: None,
                email: None,
                invalid_email: None,
                invalid_number: None,
            } => ContactType::Bad {
                invalid_email: None,
                invalid_number: None,
            },
        }
    }
}

impl ContactStorage {
    /// for updating from the old registration details type
    pub fn convert(old: ExitRegistrationDetails) -> Option<Self> {
        match old {
            ExitRegistrationDetails {
                phone: Some(phone),
                email: Some(email),
                phone_code: _,
                email_code: _,
            } => match (phone.parse(), email.parse()) {
                (Ok(validated_phone), Ok(validated_email)) => Some(ContactStorage {
                    number: Some(validated_phone),
                    email: Some(validated_email),
                    invalid_email: None,
                    invalid_number: None,
                }),
                (Err(_e), Ok(validated_email)) => Some(ContactStorage {
                    email: Some(validated_email),
                    number: None,
                    invalid_email: None,
                    invalid_number: None,
                }),
                (Ok(validated_phone), Err(_e)) => Some(ContactStorage {
                    number: Some(validated_phone),
                    email: None,
                    invalid_email: None,
                    invalid_number: None,
                }),
                (Err(_ea), Err(_eb)) => Some(ContactStorage {
                    number: None,
                    email: None,
                    invalid_email: Some(email),
                    invalid_number: Some(phone),
                }),
            },
            ExitRegistrationDetails {
                phone: Some(phone),
                email: None,
                phone_code: _,
                email_code: _,
            } => match phone.parse() {
                Ok(validated_phone) => Some(ContactStorage {
                    number: Some(validated_phone),
                    email: None,
                    invalid_email: None,
                    invalid_number: None,
                }),
                Err(_e) => Some(ContactStorage {
                    number: None,
                    email: None,
                    invalid_number: Some(phone),
                    invalid_email: None,
                }),
            },
            ExitRegistrationDetails {
                phone: None,
                email: Some(email),
                phone_code: _,
                email_code: _,
            } => match email.parse() {
                Ok(validated_email) => Some(ContactStorage {
                    email: Some(validated_email),
                    number: None,
                    invalid_email: None,
                    invalid_number: None,
                }),
                Err(_e) => Some(ContactStorage {
                    email: None,
                    number: None,
                    invalid_email: Some(email),
                    invalid_number: None,
                }),
            },
            ExitRegistrationDetails {
                phone: None,
                email: None,
                phone_code: _,
                email_code: _,
            } => None,
        }
    }
}

impl From<ContactType> for ExitRegistrationDetails {
    fn from(ct: ContactType) -> Self {
        match ct {
            ContactType::Both { number, email } => ExitRegistrationDetails {
                phone: Some(number.to_string()),
                email: Some(email.to_string()),
                email_code: None,
                phone_code: None,
            },
            ContactType::Email { email } => ExitRegistrationDetails {
                phone: None,
                email: Some(email.to_string()),
                email_code: None,
                phone_code: None,
            },
            ContactType::Phone { number } => ExitRegistrationDetails {
                phone: Some(number.to_string()),
                email: None,
                email_code: None,
                phone_code: None,
            },
            ContactType::Bad {
                invalid_email,
                invalid_number,
            } => ExitRegistrationDetails {
                phone: invalid_number,
                email: invalid_email,
                email_code: None,
                phone_code: None,
            },
        }
    }
}

impl From<ContactStorage> for ExitRegistrationDetails {
    fn from(cs: ContactStorage) -> Self {
        let ct: ContactType = cs.into();
        ct.into()
    }
}
