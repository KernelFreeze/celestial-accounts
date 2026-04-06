mod account;
mod audit_log;
mod authorization_code;
mod client;
mod consent_grant;
mod credential;
mod email;
mod invitation;
mod membership;
mod organization;
mod password_reset_token;
mod refresh_token;
mod session;

pub use account::*;
pub use audit_log::*;
pub use authorization_code::*;
pub use client::*;
pub use consent_grant::*;
pub use credential::*;
pub use email::*;
pub use invitation::*;
pub use membership::*;
pub use organization::*;
pub use password_reset_token::*;
pub use refresh_token::*;
pub use session::*;

macro_rules! pg_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident ($sql_type:ty) { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(::diesel::expression::AsExpression, ::diesel::deserialize::FromSqlRow)]
        #[diesel(sql_type = $sql_type)]
        $vis enum $name {
            $($variant),+
        }

        impl ::diesel::serialize::ToSql<$sql_type, ::diesel::pg::Pg> for $name {
            fn to_sql<'b>(
                &'b self,
                out: &mut ::diesel::serialize::Output<'b, '_, ::diesel::pg::Pg>,
            ) -> ::diesel::serialize::Result {
                let s = match self {
                    $(Self::$variant => $text),+
                };
                ::std::io::Write::write_all(out, s.as_bytes())?;
                Ok(::diesel::serialize::IsNull::No)
            }
        }

        impl ::diesel::deserialize::FromSql<$sql_type, ::diesel::pg::Pg> for $name {
            fn from_sql(
                bytes: <::diesel::pg::Pg as ::diesel::backend::Backend>::RawValue<'_>,
            ) -> ::diesel::deserialize::Result<Self> {
                let s = ::std::str::from_utf8(bytes.as_bytes())?;
                match s {
                    $($text => Ok(Self::$variant),)+
                    other => Err(format!("unknown {} value: {other}", stringify!($name)).into()),
                }
            }
        }
    };
}

pub(crate) use pg_enum;
