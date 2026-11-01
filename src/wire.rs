//! The form every one-octet number on the wire takes in the public API.

/// Defines a type for a one-octet number on the wire that RFC 9580 names some
/// values of: a newtype over the octet, a constant for each named value,
/// `number`, and `Display` and `Debug` that print the name, or `$unnamed` and
/// the number for a value without one.
///
/// Every octet is a value a packet can carry, so the type is a newtype rather
/// than an enum with a variant for unknown values: a value named later would
/// otherwise move out of a caller's match arm for unknown values into a
/// variant of its own.
///
/// ```text
/// wire_number! {
///     /// The type's documentation.
///     pub struct Example;
///     unnamed = "example";
///     /// The constant's documentation.
///     const FIRST = 1, "First";
/// }
/// ```
macro_rules! wire_number {
    (
        $(#[$meta:meta])*
        pub struct $name:ident;
        unnamed = $unnamed:literal;
        $(
            $(#[$constant_meta:meta])*
            const $constant:ident = $value:literal, $display:literal;
        )*
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub(crate) u8);

        impl $name {
            $(
                $(#[$constant_meta])*
                pub const $constant: $name = $name($value);
            )*

            /// The number on the wire.
            pub const fn number(self) -> u8 {
                self.0
            }

            /// The name RFC 9580 gives the value, if it gives one.
            const fn name(self) -> Option<&'static str> {
                Some(match self.0 {
                    $($value => $display,)*
                    _ => return None,
                })
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, concat!($unnamed, " {}"), self.0),
                }
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "({}: {})"), self.0, self)
            }
        }
    };
}

pub(crate) use wire_number;
