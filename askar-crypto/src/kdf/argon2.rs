//! Argon2 key derivation from a password

pub use argon2::{Algorithm, Version};

use crate::{error::Error, key::KeyMaterial};

/// The length of the password salt
pub const SALT_LENGTH: usize = 16;

/// Standard parameters for 'interactive' level
pub const PARAMS_INTERACTIVE: Params = Params {
    alg: Algorithm::Argon2i,
    version: Version::V0x13,
    mem_cost: 32768,
    time_cost: 4,
};
/// Standard parameters for 'moderate' level
pub const PARAMS_MODERATE: Params = Params {
    alg: Algorithm::Argon2i,
    version: Version::V0x13,
    mem_cost: 131072,
    time_cost: 6,
};

/// Parameters to the argon2 key derivation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    alg: Algorithm,
    version: Version,
    mem_cost: u32,
    time_cost: u32,
}

/// Struct wrapping the KDF functionality
#[derive(Debug)]
pub struct Argon2<'a> {
    password: &'a [u8],
    salt: &'a [u8],
    params: Params,
}

impl<'a> Argon2<'a> {
    /// Create a new Argon2 key derivation instance
    pub fn new(password: &'a [u8], salt: &'a [u8], params: Params) -> Result<Self, Error> {
        if salt.len() < SALT_LENGTH {
            return Err(err_msg!(Usage, "Invalid salt for argon2i hash"));
        }
        Ok(Self {
            password,
            salt,
            params,
        })
    }
}

impl KeyMaterial for Argon2<'_> {
    fn key_material_max_len(&self) -> Option<usize> {
        Some(u32::MAX as usize)
    }

    fn copy_key_material(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() > u32::MAX as usize {
            return Err(err_msg!(
                Usage,
                "Output length exceeds max for argon2i hash"
            ));
        }
        let mut pbuild = argon2::ParamsBuilder::new();
        pbuild.m_cost(self.params.mem_cost).unwrap();
        pbuild.t_cost(self.params.time_cost).unwrap();
        argon2::Argon2::new(
            self.params.alg,
            self.params.version,
            pbuild.params().unwrap(),
        )
        .hash_password_into(self.password, self.salt, buf)
        .map_err(|_| err_msg!(Unexpected, "Error deriving key"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected() {
        let pass = b"my password";
        let salt = b"long enough salt";
        let mut output = [0u8; 32];
        Argon2::new(pass, salt, PARAMS_INTERACTIVE)
            .unwrap()
            .copy_key_material(&mut output)
            .unwrap();
        assert_eq!(
            output,
            hex!("9ef87bcf828c46c0136a0d1d9e391d713f75b327c6dc190455bd36c1bae33259")
        );
    }
}
