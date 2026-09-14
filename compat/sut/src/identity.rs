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
//! Responsible for: turning the credential command-line arguments into one to three [`Account`]
//! values (main, alt, tenant), refusing every way two accounts can collapse into one, and resolving a verified access
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
    /// The identities besides the primary one, in command-line order, each with the role its
    /// banner line names: `alt` for the cross-account cases, `tenant` for the Ceph s3-tests
    /// `[s3 tenant]` section.
    others: Vec<(&'static str, Account)>,
}

impl Accounts {
    /// Builds the served identity set from the raw arguments.
    ///
    /// The second (`alt`) and third (`tenant`) identities exist only when the operator named them.
    /// Each one that does exist must be distinct from every other in every field that could
    /// otherwise make two of them the same principal.
    ///
    /// The third identity exists because Ceph s3-tests sweeps its bucket prefix as `[s3 tenant]`
    /// before and after **every** case. Against a service that does not know that key, all but a
    /// handful of the ~740 selected cases error in setup and nothing is measured (rustfs/backlog#1764).
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] when an additional identity is mentioned without both halves
    /// of its credential pair, when a supplied value is empty, or when two identities share an
    /// access key, a secret, an owner id or a display name.
    pub(crate) fn build(primary: AccountArgs, secondary: AccountArgs, tenant: AccountArgs) -> Result<Self, io::Error> {
        let primary = complete(primary, DEFAULT_ACCESS_KEY, DEFAULT_SECRET_KEY, "--access-key", "--secret-key")?;
        let mut served: Vec<(&'static str, Account)> = vec![("main", primary)];
        for (role, args, access_key_flag, secret_key_flag) in [
            ("alt", secondary, "--alt-access-key", "--alt-secret-key"),
            ("tenant", tenant, "--tenant-access-key", "--tenant-secret-key"),
        ] {
            if !args.is_mentioned() {
                continue;
            }
            let account = complete_other(role, args, access_key_flag, secret_key_flag)?;
            for (served_role, served_account) in &served {
                refuse_collapse(served_role, served_account, role, &account)?;
            }
            served.push((role, account));
        }
        let (_, primary) = served.remove(0);
        Ok(Self { primary, others: served })
    }

    /// Every configured identity, the bucket-owning one first.
    pub(crate) fn all(&self) -> impl Iterator<Item = &Account> {
        self.roles().map(|(_, account)| account)
    }

    /// Every configured identity with the role name its banner line uses, the primary (`main`)
    /// first.
    pub(crate) fn roles(&self) -> impl Iterator<Item = (&'static str, &Account)> {
        std::iter::once(("main", &self.primary)).chain(self.others.iter().map(|(role, account)| (*role, account)))
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

/// Completes an additional identity, which has no defaults for its credential pair.
fn complete_other(role: &str, args: AccountArgs, access_key_flag: &str, secret_key_flag: &str) -> Result<Account, io::Error> {
    if args.access_key.is_none() || args.secret_key.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the {role} identity needs both {access_key_flag} and {secret_key_flag}; half a \
                 credential pair cannot sign anything, and the cases that use it would report a \
                 signature failure rather than the authorization difference they are measuring"
            ),
        ));
    }
    complete(args, "", "", access_key_flag, secret_key_flag)
}

/// Refuses an empty value for a named flag.
fn refuse_empty(flag: &str, value: &str) -> Result<(), io::Error> {
    if value.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{flag} must not be empty")));
    }
    Ok(())
}

/// Refuses two identities that share an access key, a secret, an owner id or a display name.
///
/// The message says what a shared value costs, because the cost is not obvious: nothing fails, and
/// the cases that exist to measure the difference between the two identities go green.
fn refuse_collapse(first_role: &str, first: &Account, second_role: &str, second: &Account) -> Result<(), io::Error> {
    for (field, left, right) in [
        ("access key", &first.access_key, &second.access_key),
        ("secret key", &first.secret_key, &second.secret_key),
        ("owner id", &first.owner_id, &second.owner_id),
        ("display name", &first.display_name, &second.display_name),
    ] {
        if left == right {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the {first_role} and {second_role} identities share a {field}. They would be one \
                     principal, and every cross-account, cross-tenant and ACL case measured against \
                     them would pass without the service ever making the distinction they are \
                     written to measure"
                ),
            ));
        }
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
        let accounts = Accounts::build(AccountArgs::default(), AccountArgs::default(), AccountArgs::default())
            .expect("no argument is valid");
        let served = served(&accounts);
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].access_key, "AKIDEXAMPLE");
        assert_eq!(served[0].secret_key, "secret");
    }

    /// Positive — an unnamed owner id follows the access key, so two identities never share one.
    #[test]
    fn an_unnamed_owner_id_follows_the_access_key() {
        let accounts = Accounts::build(args("MAIN", "main-secret"), args("ALT", "alt-secret"), AccountArgs::default())
            .expect("two distinct pairs");
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
        let accounts = Accounts::build(primary, secondary, AccountArgs::default()).expect("two distinct identities");
        assert_eq!(accounts.owner_of("MAIN"), Some("s3gate-main"));
        assert_eq!(accounts.owner_of("ALT"), Some("s3gate-alt"));
        assert_eq!(accounts.owner_of("NEITHER"), None);
    }

    /// Negative — a shared access key is the plainest way to make two identities one principal.
    #[test]
    fn n_a_shared_access_key_is_refused() {
        let error = Accounts::build(args("SAME", "main-secret"), args("SAME", "alt-secret"), AccountArgs::default())
            .expect_err("a collapse");
        assert!(error.to_string().contains("access key"), "{error}");
    }

    /// Negative — a shared secret makes one leaked value authenticate as both principals.
    #[test]
    fn n_a_shared_secret_is_refused() {
        let error = Accounts::build(args("MAIN", "same-secret"), args("ALT", "same-secret"), AccountArgs::default())
            .expect_err("a collapse");
        assert!(error.to_string().contains("secret key"), "{error}");
    }

    /// Negative — a shared owner id is the collapse that survives distinct credentials.
    #[test]
    fn n_a_shared_owner_id_is_refused() {
        let mut primary = args("MAIN", "main-secret");
        primary.owner_id = Some("one-account".to_owned());
        let mut secondary = args("ALT", "alt-secret");
        secondary.owner_id = Some("one-account".to_owned());
        let error = Accounts::build(primary, secondary, AccountArgs::default()).expect_err("a collapse");
        assert!(error.to_string().contains("owner id"), "{error}");
    }

    /// Negative — a shared display name makes every owner and grantee assertion unfalsifiable.
    #[test]
    fn n_a_shared_display_name_is_refused() {
        let mut primary = args("MAIN", "main-secret");
        primary.display_name = Some("one-name".to_owned());
        let mut secondary = args("ALT", "alt-secret");
        secondary.display_name = Some("one-name".to_owned());
        let error = Accounts::build(primary, secondary, AccountArgs::default()).expect_err("a collapse");
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
        let error = Accounts::build(AccountArgs::default(), secondary, AccountArgs::default()).expect_err("half a pair");
        assert!(error.to_string().contains("needs both --alt-access-key and --alt-secret-key"), "{error}");

        let secondary = AccountArgs {
            owner_id: Some("s3gate-alt".to_owned()),
            ..AccountArgs::default()
        };
        let error = Accounts::build(AccountArgs::default(), secondary, AccountArgs::default()).expect_err("an owner id alone");
        assert!(error.to_string().contains("needs both --alt-access-key and --alt-secret-key"), "{error}");

        // The other mistake, and the other diagnosis: the flag was given, and given as nothing.
        let secondary = AccountArgs {
            access_key: Some("ALT".to_owned()),
            secret_key: Some(String::new()),
            ..AccountArgs::default()
        };
        let error = Accounts::build(AccountArgs::default(), secondary, AccountArgs::default()).expect_err("an empty secret");
        assert!(error.to_string().contains("--alt-secret-key must not be empty"), "{error}");
    }

    /// Negative — an empty value is not a value; it is a credential nothing can present.
    #[test]
    fn n_an_empty_credential_is_refused() {
        let primary = AccountArgs {
            access_key: Some(String::new()),
            ..AccountArgs::default()
        };
        assert!(Accounts::build(primary, AccountArgs::default(), AccountArgs::default()).is_err());

        let mut primary = args("MAIN", "main-secret");
        primary.owner_id = Some(String::new());
        assert!(Accounts::build(primary, AccountArgs::default(), AccountArgs::default()).is_err());
    }

    /// Positive — a third (tenant) identity is served, resolves to its own owner, and is named
    /// `tenant` in the banner roles.
    #[test]
    fn a_tenant_identity_is_served_as_its_own_principal() {
        let accounts = Accounts::build(args("MAIN", "main-secret"), args("ALT", "alt-secret"), args("TENANT", "tenant-secret"))
            .expect("three distinct identities");
        let roles: Vec<&str> = accounts.roles().map(|(role, _)| role).collect();
        assert_eq!(roles, ["main", "alt", "tenant"]);
        assert_eq!(accounts.owner_of("TENANT"), Some("TENANT"));
        assert_eq!(accounts.owner_of("ALT"), Some("ALT"));
        assert_eq!(accounts.data_root_owner().0, "MAIN");
    }

    /// Positive — the tenant role label follows the tenant, not its position, when no alt is given.
    #[test]
    fn a_tenant_without_an_alt_is_still_labelled_tenant() {
        let accounts = Accounts::build(args("MAIN", "main-secret"), AccountArgs::default(), args("TENANT", "t-secret"))
            .expect("two distinct identities");
        let roles: Vec<&str> = accounts.roles().map(|(role, _)| role).collect();
        assert_eq!(roles, ["main", "tenant"]);
    }

    /// Negative — the tenant may not collapse into the alt identity any more than into the main
    /// one; the cross-tenant cases would then pass for the wrong reason.
    #[test]
    fn n_a_tenant_sharing_the_alt_owner_id_is_refused() {
        let mut secondary = args("ALT", "alt-secret");
        secondary.owner_id = Some("one-account".to_owned());
        let mut tenant = args("TENANT", "tenant-secret");
        tenant.owner_id = Some("one-account".to_owned());
        let error = Accounts::build(args("MAIN", "main-secret"), secondary, tenant).expect_err("a tenant/alt collapse");
        let message = error.to_string();
        assert!(message.contains("alt and tenant identities share a owner id"), "{message}");

        let error = Accounts::build(args("MAIN", "main-secret"), AccountArgs::default(), args("MAIN", "t-secret"))
            .expect_err("a tenant/main collapse");
        assert!(error.to_string().contains("main and tenant identities share a access key"), "{error}");
    }

    /// Negative — half a tenant credential pair is refused and names the tenant flags.
    #[test]
    fn n_a_half_supplied_tenant_identity_is_refused() {
        let tenant = AccountArgs {
            access_key: Some("TENANT".to_owned()),
            ..AccountArgs::default()
        };
        let error = Accounts::build(AccountArgs::default(), AccountArgs::default(), tenant).expect_err("half a pair");
        assert!(
            error
                .to_string()
                .contains("needs both --tenant-access-key and --tenant-secret-key"),
            "{error}"
        );
    }
}
