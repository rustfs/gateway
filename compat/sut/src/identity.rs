// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The credential identities the launcher serves, and what makes the second one a real principal.
//!
//! Responsible for: turning the credential command-line arguments into one or two [`Account`]
//! values, refusing every way two accounts can collapse into one, and resolving a verified access
//! key id back to the account that owns it.
//! NOT responsible for: verifying a signature (`rustfs-gateway-sig` does that), deciding what an
//! account may do (`crate::ownership`), or persisting anything.
//! Upstream: `crate::parse_options`. Downstream: `crate::service`, which registers these with the
//! `SigV4Authenticator` and hands the same set to the authorizer and the bucket-owner source.
//!
//! # Why the collapse checks are the point of this file
//!
//! The external suites that need a second identity — the Ceph s3-tests ACL and cross-account
//! cases — authenticate as the second identity while the first owns the bucket. Two key pairs
//! that resolve to one principal do not make those cases fail. They make them **pass**, against a
//! service that never made the distinction they are measuring. That is a check that cannot fail,
//! and this file exists so that it cannot be configured into being.

use std::io;

/// One credential identity, and everything that distinguishes it from the other one.
#[derive(Clone, Debug)]
pub(crate) struct Account {
    /// The access key id presented in the `Credential=` scope of a signed request.
    pub(crate) access_key: String,
    /// The signing secret. Never printed, never logged, never rendered into a response.
    pub(crate) secret_key: String,
    /// The account identifier this principal owns buckets as. Compared byte-for-byte with
    /// `x-amz-expected-bucket-owner`, and the key the bucket-owner registry records.
    pub(crate) owner_id: String,
    /// The human-readable name a suite expects in an owner or grantee assertion.
    pub(crate) display_name: String,
}

/// The credential arguments exactly as they arrived, before any default or check is applied.
///
/// Kept separate from [`Account`] so that "the operator said nothing" and "the operator said this"
/// remain distinguishable: a partially supplied second identity must be refused rather than
/// silently completed from the first one's values.
#[derive(Clone, Debug, Default)]
pub(crate) struct AccountArgs {
    pub(crate) access_key: Option<String>,
    pub(crate) secret_key: Option<String>,
    pub(crate) owner_id: Option<String>,
    pub(crate) display_name: Option<String>,
}

impl AccountArgs {
    /// Whether the operator mentioned this identity at all.
    fn is_mentioned(&self) -> bool {
        self.access_key.is_some() || self.secret_key.is_some() || self.owner_id.is_some() || self.display_name.is_some()
    }
}

/// The default credential pair, unchanged from the launcher's first version.
///
/// There is no default for the **second** identity on purpose: a service that always served two
/// principals would let a suite that forgot to configure the second one still pass its
/// cross-account cases, which is the failure this whole file is written against.
const DEFAULT_ACCESS_KEY: &str = "AKIDEXAMPLE";
const DEFAULT_SECRET_KEY: &str = "secret";

/// Every identity this launcher serves.
#[derive(Clone, Debug)]
pub(crate) struct Accounts {
    primary: Account,
    secondary: Option<Account>,
}

impl Accounts {
    /// Builds the served identity set from the raw arguments.
    ///
    /// The second identity exists only when the operator named it. When it does exist, it must be
    /// distinct from the first in every field that could otherwise make the two the same
    /// principal.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] when a second identity is mentioned without both halves of
    /// its credential pair, when a supplied value is empty, or when the two identities share an
    /// access key, a secret, an owner id or a display name.
    pub(crate) fn build(primary: AccountArgs, secondary: AccountArgs) -> Result<Self, io::Error> {
        let primary = complete(primary, DEFAULT_ACCESS_KEY, DEFAULT_SECRET_KEY, "--access-key", "--secret-key")?;
        let Some(secondary) = secondary.is_mentioned().then(|| complete_second(secondary)).transpose()? else {
            return Ok(Self {
                primary,
                secondary: None,
            });
        };
        refuse_collapse("access key", &primary.access_key, &secondary.access_key)?;
        refuse_collapse("secret key", &primary.secret_key, &secondary.secret_key)?;
        refuse_collapse("owner id", &primary.owner_id, &secondary.owner_id)?;
        refuse_collapse("display name", &primary.display_name, &secondary.display_name)?;
        Ok(Self {
            primary,
            secondary: Some(secondary),
        })
    }

    /// Every configured identity, the bucket-owning one first.
    pub(crate) fn all(&self) -> impl Iterator<Item = &Account> {
        std::iter::once(&self.primary).chain(self.secondary.as_ref())
    }

    /// The primary owner this single-tenant data root reports for every bucket and object.
    pub(crate) fn data_root_owner(&self) -> (&str, &str) {
        (&self.primary.owner_id, &self.primary.display_name)
    }

    /// The owner id a verified access key id runs as.
    ///
    /// `None` for an access key this launcher never registered. The authenticator cannot admit
    /// such a key, so the authorizer treats the case as a refusal rather than as an allowance.
    pub(crate) fn owner_of(&self, access_key_id: &str) -> Option<&str> {
        self.all()
            .find(|account| account.access_key == access_key_id)
            .map(|account| account.owner_id.as_str())
    }
}

/// Fills an identity's optional fields from its access key and refuses an empty value.
fn complete(
    args: AccountArgs,
    default_access_key: &str,
    default_secret_key: &str,
    access_key_flag: &str,
    secret_key_flag: &str,
) -> Result<Account, io::Error> {
    let access_key = args.access_key.unwrap_or_else(|| default_access_key.to_owned());
    let secret_key = args.secret_key.unwrap_or_else(|| default_secret_key.to_owned());
    refuse_empty(access_key_flag, &access_key)?;
    refuse_empty(secret_key_flag, &secret_key)?;
    // The owner id and display name default to the access key id rather than to a shared
    // constant: a shared constant would make two identities report one owner by default, which is
    // the exact collapse the explicit checks below exist to prevent.
    let owner_id = args.owner_id.unwrap_or_else(|| access_key.clone());
    let display_name = args.display_name.unwrap_or_else(|| access_key.clone());
    refuse_empty("--owner-id", &owner_id)?;
    refuse_empty("--display-name", &display_name)?;
    Ok(Account {
        access_key,
        secret_key,
        owner_id,
        display_name,
    })
}

/// Completes the second identity, which has no defaults for its credential pair.
fn complete_second(args: AccountArgs) -> Result<Account, io::Error> {
    if args.access_key.is_none() || args.secret_key.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a second identity needs both --alt-access-key and --alt-secret-key; half a credential \
             pair cannot sign anything, and the cross-account cases would report a signature \
             failure rather than the authorization difference they are measuring",
        ));
    }
    let account = complete(args, "", "", "--alt-access-key", "--alt-secret-key")?;
    Ok(account)
}

/// Refuses an empty value for a named flag.
fn refuse_empty(flag: &str, value: &str) -> Result<(), io::Error> {
    if value.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{flag} must not be empty")));
    }
    Ok(())
}

/// Refuses two identities that share the named field.
///
/// The message says what a shared value costs, because the cost is not obvious: nothing fails, and
/// the cases that exist to measure the difference between the two identities go green.
fn refuse_collapse(field: &str, primary: &str, secondary: &str) -> Result<(), io::Error> {
    if primary == secondary {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the two identities share a {field}. They would be one principal, and every \
                 cross-account and ACL case measured against them would pass without the service \
                 ever making the distinction they are written to measure"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{Account, AccountArgs, Accounts};

    fn served(accounts: &Accounts) -> Vec<&Account> {
        accounts.all().collect()
    }

    fn args(access_key: &str, secret_key: &str) -> AccountArgs {
        AccountArgs {
            access_key: Some(access_key.to_owned()),
            secret_key: Some(secret_key.to_owned()),
            ..AccountArgs::default()
        }
    }

    /// Positive — one identity is still a valid configuration, and it keeps the original defaults.
    #[test]
    fn a_single_identity_keeps_the_original_defaults() {
        let accounts = Accounts::build(AccountArgs::default(), AccountArgs::default()).expect("no argument is valid");
        let served = served(&accounts);
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].access_key, "AKIDEXAMPLE");
        assert_eq!(served[0].secret_key, "secret");
    }

    /// Positive — an unnamed owner id follows the access key, so two identities never share one.
    #[test]
    fn an_unnamed_owner_id_follows_the_access_key() {
        let accounts = Accounts::build(args("MAIN", "main-secret"), args("ALT", "alt-secret")).expect("two distinct pairs");
        let served = served(&accounts);
        assert_eq!(served.len(), 2);
        assert_eq!(served[0].owner_id, "MAIN");
        assert_eq!(served[0].display_name, "MAIN");
        assert_eq!(served[1].owner_id, "ALT");
        assert_ne!(served[0].owner_id, served[1].owner_id);
    }

    /// Positive — a verified access key resolves to its own owner id and to no other.
    #[test]
    fn each_access_key_resolves_to_its_own_owner() {
        let mut secondary = args("ALT", "alt-secret");
        secondary.owner_id = Some("s3gate-alt".to_owned());
        secondary.display_name = Some("s3gate-alt".to_owned());
        let mut primary = args("MAIN", "main-secret");
        primary.owner_id = Some("s3gate-main".to_owned());
        primary.display_name = Some("s3gate-main".to_owned());
        let accounts = Accounts::build(primary, secondary).expect("two distinct identities");
        assert_eq!(accounts.owner_of("MAIN"), Some("s3gate-main"));
        assert_eq!(accounts.owner_of("ALT"), Some("s3gate-alt"));
        assert_eq!(accounts.owner_of("NEITHER"), None);
    }

    /// Negative — a shared access key is the plainest way to make two identities one principal.
    #[test]
    fn n_a_shared_access_key_is_refused() {
        let error = Accounts::build(args("SAME", "main-secret"), args("SAME", "alt-secret")).expect_err("a collapse");
        assert!(error.to_string().contains("access key"), "{error}");
    }

    /// Negative — a shared secret makes one leaked value authenticate as both principals.
    #[test]
    fn n_a_shared_secret_is_refused() {
        let error = Accounts::build(args("MAIN", "same-secret"), args("ALT", "same-secret")).expect_err("a collapse");
        assert!(error.to_string().contains("secret key"), "{error}");
    }

    /// Negative — a shared owner id is the collapse that survives distinct credentials.
    #[test]
    fn n_a_shared_owner_id_is_refused() {
        let mut primary = args("MAIN", "main-secret");
        primary.owner_id = Some("one-account".to_owned());
        let mut secondary = args("ALT", "alt-secret");
        secondary.owner_id = Some("one-account".to_owned());
        let error = Accounts::build(primary, secondary).expect_err("a collapse");
        assert!(error.to_string().contains("owner id"), "{error}");
    }

    /// Negative — a shared display name makes every owner and grantee assertion unfalsifiable.
    #[test]
    fn n_a_shared_display_name_is_refused() {
        let mut primary = args("MAIN", "main-secret");
        primary.display_name = Some("one-name".to_owned());
        let mut secondary = args("ALT", "alt-secret");
        secondary.display_name = Some("one-name".to_owned());
        let error = Accounts::build(primary, secondary).expect_err("a collapse");
        assert!(error.to_string().contains("display name"), "{error}");
    }

    /// Negative — half a second credential pair cannot sign, so it is refused rather than guessed.
    ///
    /// The assertion is on the **distinctive** half of the diagnosis rather than on a flag name.
    /// An omitted flag and a flag supplied as the empty string are different mistakes with
    /// different fixes, and both are refused; asserting only on the flag name made the omission
    /// check unfalsifiable — deleting it left the empty-value refusal answering in its place, and
    /// the test stayed green. Measured, with the mutation named in the pull request.
    #[test]
    fn n_a_half_supplied_second_identity_is_refused() {
        let secondary = AccountArgs {
            access_key: Some("ALT".to_owned()),
            ..AccountArgs::default()
        };
        let error = Accounts::build(AccountArgs::default(), secondary).expect_err("half a pair");
        assert!(error.to_string().contains("needs both --alt-access-key and --alt-secret-key"), "{error}");

        let secondary = AccountArgs {
            owner_id: Some("s3gate-alt".to_owned()),
            ..AccountArgs::default()
        };
        let error = Accounts::build(AccountArgs::default(), secondary).expect_err("an owner id alone");
        assert!(error.to_string().contains("needs both --alt-access-key and --alt-secret-key"), "{error}");

        // The other mistake, and the other diagnosis: the flag was given, and given as nothing.
        let secondary = AccountArgs {
            access_key: Some("ALT".to_owned()),
            secret_key: Some(String::new()),
            ..AccountArgs::default()
        };
        let error = Accounts::build(AccountArgs::default(), secondary).expect_err("an empty secret");
        assert!(error.to_string().contains("--alt-secret-key must not be empty"), "{error}");
    }

    /// Negative — an empty value is not a value; it is a credential nothing can present.
    #[test]
    fn n_an_empty_credential_is_refused() {
        let primary = AccountArgs {
            access_key: Some(String::new()),
            ..AccountArgs::default()
        };
        assert!(Accounts::build(primary, AccountArgs::default()).is_err());

        let mut primary = args("MAIN", "main-secret");
        primary.owner_id = Some(String::new());
        assert!(Accounts::build(primary, AccountArgs::default()).is_err());
    }
}
