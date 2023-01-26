use core::fmt::{self, Debug, Display, Formatter, Write};

/// A utility type used to print or serialize a byte string as hex
#[derive(Debug)]
pub struct HexRepr<B>(pub B);

impl<B: AsRef<[u8]>> Display for HexRepr<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for c in self.0.as_ref() {
            f.write_fmt(format_args!("{:02x}", c))?;
        }
        Ok(())
    }
}

// Compare to another hex value as [u8]
impl<B: AsRef<[u8]>> PartialEq<[u8]> for HexRepr<B> {
    fn eq(&self, other: &[u8]) -> bool {
        struct CmpWrite<'s>(::core::slice::Iter<'s, u8>);

        impl Write for CmpWrite<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                for c in s.as_bytes() {
                    if self.0.next() != Some(c) {
                        return Err(fmt::Error);
                    }
                }
                Ok(())
            }
        }

        write!(&mut CmpWrite(other.iter()), "{}", self).is_ok()
    }
}

impl<B: AsRef<[u8]>> PartialEq<&str> for HexRepr<B> {
    fn eq(&self, other: &&str) -> bool {
        self == other.as_bytes()
    }
}

/// A utility type for debug printing of byte strings
pub struct MaybeStr<'a>(pub &'a [u8]);

impl Debug for MaybeStr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Ok(sval) = core::str::from_utf8(self.0) {
            write!(f, "{:?}", sval)
        } else {
            write!(f, "<{}>", HexRepr(self.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_repr_output() {
        assert_eq!(format!("{}", HexRepr(&[])), "");
        assert_eq!(format!("{}", HexRepr(&[255, 0, 255, 0])), "ff00ff00");
    }

    #[test]
    fn hex_repr_cmp() {
        assert_eq!(HexRepr(&[0, 255, 0, 255]), "00ff00ff");
        assert_ne!(HexRepr(&[100, 101, 102]), "00ff00ff");
    }

    #[test]
    fn maybe_str_output() {
        assert_eq!(format!("{:?}", MaybeStr(&[])), "\"\"");
        assert_eq!(format!("{:?}", MaybeStr(&[255, 0])), "<ff00>");
    }
}
