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

//! Which byte of the `Host` header may become a bucket name, and which may not.
//!
//! Responsible for: the label-boundary rule that separates `bucket.s3.example.com` from
//! `evils3.example.com`, the unconditional path-style fallback for every host the deployment did
//! not configure, the prefix-shape table that decides bucket and region, the base-domain
//! configuration refusals, and the two properties the diagnostic must have — it fires only when a
//! request really looks virtual-hosted, and it never changes the resolution.
//! NOT responsible for: how the effective host is determined (`rustfs-gateway-http` did that once
//! at acceptance), what the canonical request signs (`rustfs-gateway-sig`, over
//! `EffectiveHost::raw_for_signing`), or whether the named bucket exists.
//! Upstream: the facade's `VirtualHostStyle`, `PathStyleOnly` and `MetaView`. Downstream: nothing;
//! this is a leaf test.
//!
//! # Why a resolution test rather than a response test
//!
//! A conformance case sees a status and a body. `conformance/cases/host/**` uses that to pin the
//! outcomes an attacker cares about, and it can: a bucket resolved from the wrong host answers
//! with the wrong object. What no response can show is the *shape* of the answer — that a host was
//! read as path-style rather than as a virtual host whose bucket happens to coincide, that the
//! region label was carried rather than dropped, that a diagnostic was raised and then not acted
//! on. Those are asserted here, on the value the resolver returns.

use rustfs_gateway::{
    Addressing, DomainError, HostQuery, HostResolver, Limits, MetaView, PathStyleOnly, ResolvedHost, TargetKind, TargetOrigin,
    VhostHint, VirtualHostStyle, WireRequest,
};

/// The two base domains most cases below are configured with.
fn two_domains() -> VirtualHostStyle {
    VirtualHostStyle::new(["s3.example.com", "mys3.com"]).expect("both base domains are well formed")
}

/// Accepts a request and asks a resolver about it.
fn resolve(resolver: &dyn HostResolver, host: &str, method: &str, path: &str) -> ResolvedHost {
    let request = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .body(())
        .expect("the fixture request is well formed");
    let accepted = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    resolver.resolve(&HostQuery {
        host: accepted.host(),
        path: accepted.raw_path().as_str(),
        method: accepted.method(),
    })
}

/// The bucket a host named, or `None` when the request is path-style.
fn bucket_of(resolved: &ResolvedHost) -> Option<String> {
    resolved.bucket().map(|bucket| bucket.as_str().to_owned())
}

/// A fixed sequence makes a failed sample reproducible without weakening the input space.
fn next_host_sample(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn c_host_0032_fifty_thousand_suffix_collisions_remain_path_style() {
    let resolver = two_domains();
    let mut state = 0x6c61_6265_6c73_7566;
    for _ in 0..50_000 {
        let label = next_host_sample(&mut state);
        let domain = if label & 1 == 0 { "mys3.com" } else { "s3.example.com" };
        let host = format!("bucket-{label:x}{domain}");
        let resolved = resolve(&resolver, &host, "GET", "/bucket/key");
        assert_eq!(resolved.addressing, Addressing::Path, "host {host}");
    }
}

#[test]
fn c_host_0032_fifty_thousand_foreign_suffixes_remain_path_style() {
    let resolver = two_domains();
    let mut state = 0x666f_7265_6967_6e73;
    for _ in 0..50_000 {
        let label = next_host_sample(&mut state);
        let domain = if label & 1 == 0 { "mys3.com" } else { "s3.example.com" };
        let host = format!("bucket-{label:x}.{domain}.outside-{label:x}.net");
        let resolved = resolve(&resolver, &host, "GET", "/bucket/key");
        assert_eq!(resolved.addressing, Addressing::Path, "host {host}");
    }
}

#[test]
fn generated_matching_hosts_still_name_their_own_bucket() {
    let resolver = two_domains();
    let mut state = 0x706f_7369_7469_7665;
    for _ in 0..10_000 {
        let label = next_host_sample(&mut state);
        let bucket = format!("bucket-{label:x}");
        let domain = if label & 1 == 0 { "mys3.com" } else { "s3.example.com" };
        let host = format!("{}.{domain}.:9000", bucket.to_ascii_uppercase());
        let resolved = resolve(&resolver, &host, "GET", "/key");
        assert_eq!(bucket_of(&resolved).as_deref(), Some(bucket.as_str()), "host {host}");
    }
}

#[test]
fn c_host_0031_one_hundred_thousand_raw_hosts_preserve_signing_bytes() {
    let resolver = two_domains();
    let mut state = 0x7261_772d_686f_7374;
    let mut accepted_count = 0;
    let mut rejected_count = 0;
    for sample in 0..100_000 {
        let value = next_host_sample(&mut state);
        let raw = match sample % 5 {
            0 => format!("BUCKET-{value:x}.MYS3.COM.:9000").into_bytes(),
            1 => format!("bucket-{value:x}mys3.com").into_bytes(),
            2 => b"[2001:db8::1]:9000".to_vec(),
            3 => vec![b'.'; (value as usize % 1024) + 1],
            _ => (0..value % 1024).map(|_| next_host_sample(&mut state) as u8).collect(),
        };
        let Ok(header) = http::HeaderValue::from_bytes(&raw) else {
            rejected_count += 1;
            continue;
        };
        let mut request = http::Request::new(());
        *request.uri_mut() = http::Uri::from_static("/bucket/key");
        request.headers_mut().insert(http::header::HOST, header);
        let Ok(accepted) = WireRequest::accept(request, &Limits::default()) else {
            rejected_count += 1;
            continue;
        };
        accepted_count += 1;
        let host = accepted.host().host_without_port();
        let has_domain_labels = ["mys3.com", "s3.example.com"].iter().any(|domain| {
            // Compare complete labels independently of the production byte-offset matcher.
            host.rsplit('.').take(domain.split('.').count()).eq(domain.rsplit('.'))
        });
        let resolved = resolver.resolve(&HostQuery {
            host: accepted.host(),
            path: accepted.raw_path().as_str(),
            method: accepted.method(),
        });
        if !has_domain_labels {
            assert_eq!(resolved.addressing, Addressing::Path, "raw host {raw:?}");
        }
        assert_eq!(accepted.host().raw_for_signing().as_str().as_bytes(), raw);
    }
    assert!(accepted_count >= 60_000, "the resolver must receive the accepted host shapes");
    assert!(rejected_count > 0, "the sample must also exercise the acceptance boundary");
}

// ---------------------------------------------------------------------------------------------
// Positive — the shapes that must resolve.
// ---------------------------------------------------------------------------------------------

/// A single label in front of a configured base domain is the bucket, and the path is all key.
#[test]
fn a_single_label_in_front_of_the_base_domain_is_the_bucket() {
    let resolved = resolve(&two_domains(), "conf-host.s3.example.com", "GET", "/key");
    assert_eq!(bucket_of(&resolved).as_deref(), Some("conf-host"));
    assert_eq!(resolved.region(), None);
    assert_eq!(resolved.origin(), TargetOrigin::Host);
    assert_eq!(resolved.target, TargetKind::Object);
    assert_eq!(resolved.diagnostic, None);
}

/// `<bucket>.s3.<region>.<base>` carries the region out; dropping it is s3s#481/#503.
#[test]
fn the_region_label_is_carried_out_of_the_host() {
    let resolved = resolve(&two_domains(), "conf-host.s3.us-west-2.mys3.com", "GET", "/key");
    assert_eq!(bucket_of(&resolved).as_deref(), Some("conf-host"));
    assert_eq!(resolved.region(), Some("us-west-2"));
}

/// `<bucket>.s3.<base>` is the same bucket with no region, not a two-label prefix nobody reads.
#[test]
fn the_s3_infix_form_resolves_without_a_region() {
    let resolved = resolve(&two_domains(), "conf-host.s3.mys3.com", "GET", "/key");
    assert_eq!(bucket_of(&resolved).as_deref(), Some("conf-host"));
    assert_eq!(resolved.region(), None);
}

/// Every configured domain matches, not only the first one.
#[test]
fn the_second_configured_domain_matches_too() {
    let resolved = resolve(&two_domains(), "conf-host.mys3.com", "GET", "/key");
    assert_eq!(bucket_of(&resolved).as_deref(), Some("conf-host"));
}

/// A port, a trailing root dot and an upper-case spelling are one host, and the raw bytes the
/// signature was computed over keep all three.
#[test]
fn a_port_an_upper_case_spelling_and_a_root_dot_still_match() {
    for host in [
        "conf-host.s3.example.com:9000",
        "CONF-HOST.S3.EXAMPLE.COM",
        "conf-host.s3.example.com.",
    ] {
        let resolved = resolve(&two_domains(), host, "GET", "/key");
        assert_eq!(bucket_of(&resolved).as_deref(), Some("conf-host"), "host {host}");
    }

    // The other half of the same rule: normalisation is for matching only. A signer handed the
    // normalised value would make one signature valid for all three spellings above.
    let request = http::Request::builder()
        .method("GET")
        .uri("/key")
        .header("host", "CONF-HOST.S3.EXAMPLE.COM.:9000")
        .body(())
        .expect("the fixture request is well formed");
    let accepted = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    assert_eq!(
        accepted.host().raw_for_signing().as_str(),
        "CONF-HOST.S3.EXAMPLE.COM.:9000",
        "the canonical request must see the bytes the client sent, not the resolver's copy"
    );
}

/// A configured base domain spelled in mixed case matches a lower-case host.
#[test]
fn a_base_domain_configured_in_mixed_case_still_matches() {
    let resolver = VirtualHostStyle::new(["S3.Example.COM"]).expect("case is not a configuration error");
    let resolved = resolve(&resolver, "conf-host.s3.example.com", "GET", "/key");
    assert_eq!(bucket_of(&resolved).as_deref(), Some("conf-host"));
}

/// `/` on a virtual host addresses the bucket the host named, not the service root.
#[test]
fn the_root_path_on_a_virtual_host_addresses_the_bucket() {
    let resolved = resolve(&two_domains(), "conf-host.s3.example.com", "PUT", "/");
    assert_eq!(resolved.target, TargetKind::Bucket);
    assert_eq!(bucket_of(&resolved).as_deref(), Some("conf-host"));
}

/// A single-label base domain is legal, because `bucket.localhost` is how a developer runs this.
#[test]
fn a_single_label_base_domain_is_accepted() {
    let resolver = VirtualHostStyle::new(["localhost"]).expect("a single-label base domain is a development setup");
    let resolved = resolve(&resolver, "conf-host.localhost:9000", "GET", "/key");
    assert_eq!(bucket_of(&resolved).as_deref(), Some("conf-host"));
}

// ---------------------------------------------------------------------------------------------
// Negative — the shapes that must not resolve.
// ---------------------------------------------------------------------------------------------

/// s3s#648. A host that merely *ends with* the base domain is a different domain, and reading a
/// bucket out of it hands an attacker a bucket the client never named.
#[test]
fn n_a_host_that_merely_ends_with_the_base_domain_is_not_a_subdomain() {
    for host in [
        "evils3.example.com",
        "notmys3.com",
        "xmys3.com",
        "amys3.com",
        "evil-notmys3.com",
        "attacker.evils3.example.com",
    ] {
        let resolved = resolve(&two_domains(), host, "GET", "/key");
        assert_eq!(
            bucket_of(&resolved),
            None,
            "`{host}` is not a subdomain of any configured base domain and must name no bucket"
        );
        assert_eq!(resolved.origin(), TargetOrigin::Path, "host {host}");
    }
}

/// The base domain appearing as a *prefix* of the host is the same bug read the other way round.
#[test]
fn n_the_base_domain_as_a_prefix_is_not_a_match() {
    for host in [
        // Each of these carries a configured domain as a whole label sequence, and the first three
        // put a legal bucket name in front of it: a resolver matching on containment rather than on
        // a suffix boundary reads `victim-bucket` out of them, under a domain the attacker owns.
        "victim-bucket.s3.example.com.attacker.net",
        "victim-bucket.mys3.com.evil.io",
        "victim-bucket.s3.example.com.mys3.com.evil.net",
        "s3.example.com.attacker.net",
        "mys3.com.evil.io",
        "s3.example.commercial.net",
    ] {
        let resolved = resolve(&two_domains(), host, "GET", "/key");
        assert_eq!(bucket_of(&resolved), None, "host {host}");
    }
}

/// The bare base domain names no bucket: `GET /bucket/key` on it is an ordinary path-style request.
#[test]
fn n_the_bare_base_domain_is_path_style() {
    let resolved = resolve(&two_domains(), "s3.example.com", "GET", "/conf-host/key");
    assert_eq!(bucket_of(&resolved), None);
    assert_eq!(resolved.target, TargetKind::Object);
    assert_eq!(resolved.origin(), TargetOrigin::Path);
}

/// s3s#643. Configuring domains must not break the hosts that were never configured — an IP
/// address, a reverse proxy's name, anything. Path-style has to keep working there.
#[test]
fn n_an_unconfigured_host_falls_back_to_a_working_path_style() {
    for (host, method, path, expected) in [
        ("192.168.1.1:8014", "GET", "/conf-host/key", TargetKind::Object),
        ("some-other-domain.io", "PUT", "/conf-host/key", TargetKind::Object),
        ("localhost:9000", "GET", "/conf-host", TargetKind::Bucket),
        ("some-other-domain.io", "GET", "/", TargetKind::Service),
    ] {
        let resolved = resolve(&two_domains(), host, method, path);
        assert_eq!(bucket_of(&resolved), None, "host {host}");
        assert_eq!(resolved.target, expected, "host {host}");
    }
}

/// An IPv4 literal is an address, never a virtual host — even when a configured base domain
/// happens to be a suffix of it on a label boundary. s3s#147/#150.
#[test]
fn n_an_ipv4_literal_host_is_never_virtual_hosted() {
    // `168.1.1` is a legal base domain: it is not an address, and an operator may configure it.
    // `192.168.1.1` ends with `.168.1.1`, so the boundary rule alone would read `192` as a bucket.
    let resolver = VirtualHostStyle::new(["168.1.1"]).expect("a numeric label is not an address");
    let resolved = resolve(&resolver, "192.168.1.1:8014", "GET", "/conf-host/key");
    assert_eq!(
        bucket_of(&resolved),
        None,
        "an address that happens to end with a configured domain is still an address"
    );
}

/// A bracketed IPv6 literal is an address too, and the brackets and port are not bucket material.
#[test]
fn n_an_ipv6_literal_host_is_path_style() {
    for host in ["[2001:db8::1]:9000", "[::1]:9000", "[2001:db8::1]"] {
        let resolved = resolve(&two_domains(), host, "GET", "/conf-host/key");
        assert_eq!(bucket_of(&resolved), None, "host {host}");
        assert_eq!(resolved.target, TargetKind::Object, "host {host}");
    }
}

/// A prefix that is not a legal bucket name is not repaired and not guessed at.
#[test]
fn n_a_prefix_that_is_not_a_legal_bucket_name_is_not_guessed() {
    for host in [
        "_bad_.s3.example.com",
        "ab.s3.example.com",
        "-lead.s3.example.com",
        "trail-.s3.example.com",
        "UPPER.s3.example.com.evil.net",
    ] {
        let resolved = resolve(&two_domains(), host, "GET", "/key");
        assert_eq!(bucket_of(&resolved), None, "host {host}");
    }
}

/// A dotted bucket name is not virtual-hosted: the wildcard certificate does not cover the extra
/// label, so AWS itself falls back to path style for those buckets.
#[test]
fn n_a_dotted_bucket_name_is_not_virtual_hosted() {
    let resolved = resolve(&two_domains(), "mine.dotted.bucket.mys3.com", "GET", "/key");
    assert_eq!(bucket_of(&resolved), None);
}

/// A multi-label prefix matching none of the known shapes is path-style; the resolver does not
/// pick a label and hope.
#[test]
fn n_an_unrecognised_multi_label_prefix_is_not_guessed() {
    for host in [
        "a.b.c.mys3.com",
        "conf-host.s4.mys3.com",
        "conf-host.s3.us-west-2.extra.mys3.com",
        "conf-host.s3.bad_region.mys3.com",
    ] {
        let resolved = resolve(&two_domains(), host, "GET", "/key");
        assert_eq!(bucket_of(&resolved), None, "host {host}");
    }
}

/// No IDN mapping. An A-label is not decoded, and `xn--` is a reserved bucket prefix anyway;
/// mapping here would be a second spelling for one bucket and the signature covers only one.
#[test]
fn n_a_punycode_label_is_not_mapped_to_a_bucket() {
    let resolved = resolve(&two_domains(), "xn--80ak6aa92e.s3.example.com", "GET", "/key");
    assert_eq!(bucket_of(&resolved), None);
}

/// `X-Forwarded-Host` is not an input. The resolver is handed the effective host and a path, so
/// there is no header for a hop in front of the gateway to redirect a bucket with.
#[test]
fn n_a_forwarded_host_header_cannot_reach_the_resolver() {
    let request = http::Request::builder()
        .method("GET")
        .uri("/conf-host/key")
        .header("host", "s3.example.com")
        .header("x-forwarded-host", "victim.s3.example.com")
        .header("forwarded", "host=victim.s3.example.com")
        .body(())
        .expect("the fixture request is well formed");
    let accepted = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    let resolved = two_domains().resolve(&HostQuery {
        host: accepted.host(),
        path: accepted.raw_path().as_str(),
        method: accepted.method(),
    });
    assert_eq!(bucket_of(&resolved), None, "a forwarded header must not name a bucket");
    assert_eq!(resolved.origin(), TargetOrigin::Path);
}

/// A base domain that cannot mean one thing is refused at assembly, not ignored at request time.
#[test]
fn n_an_unusable_base_domain_is_refused_when_the_resolver_is_built() {
    for domain in [
        "",
        ".s3.example.com",
        "s3.example.com.",
        "s3..example.com",
        "192.168.1.1",
        "[2001:db8::1]",
        "s3.example.com:9000",
        "s3.example.com/path",
        "s3.exa mple.com",
        "s3.ex\u{e4}mple.com",
        "s3.example.com\u{7f}",
    ] {
        assert!(
            VirtualHostStyle::new([domain]).is_err(),
            "`{domain}` is not a usable base domain and must not be accepted silently"
        );
    }
    // And the reason is a value, not a string a caller has to parse.
    assert_eq!(VirtualHostStyle::new([""]).unwrap_err(), DomainError::Empty);
    assert_eq!(VirtualHostStyle::new(["192.168.1.1"]).unwrap_err(), DomainError::AddressLiteral);
}

/// Overlapping base domains resolve by the longest match, and the answer does not depend on the
/// order the operator listed them in.
#[test]
fn n_overlapping_base_domains_resolve_by_the_longest_match() {
    let forwards = VirtualHostStyle::new(["example.com", "foo.example.com"]).expect("both are well formed");
    let backwards = VirtualHostStyle::new(["foo.example.com", "example.com"]).expect("both are well formed");
    for resolver in [&forwards, &backwards] {
        let resolved = resolve(resolver, "conf-host.s3.foo.example.com", "GET", "/key");
        assert_eq!(bucket_of(&resolved).as_deref(), Some("conf-host"));
        assert_eq!(
            resolved.region(),
            None,
            "the shorter domain would have read `foo` as a region; the longest match must win"
        );
    }
}

/// The hint fires on a request that looks virtual-hosted and reaches a deployment that serves no
/// such domain — and it does not touch the resolution. s3s#259.
#[test]
fn n_the_diagnostic_never_changes_the_resolution() {
    let resolved = resolve(&two_domains(), "conf-host.other.example.com", "PUT", "/");
    assert_eq!(resolved.diagnostic, Some(VhostHint::LooksLikeVhostButNotConfigured));
    assert_eq!(bucket_of(&resolved), None, "a hint is a message, not a resolution");
    assert_eq!(resolved.origin(), TargetOrigin::Path);
    assert_eq!(resolved.target, TargetKind::Service);

    // The default resolver is the "no domain configured at all" case, which is the deployment
    // s3s#259 is about, and it raises the same hint.
    let by_default = resolve(&PathStyleOnly, "conf-host.other.example.com", "PUT", "/");
    assert_eq!(by_default.diagnostic, Some(VhostHint::LooksLikeVhostButNotConfigured));
    assert_eq!(by_default.target, TargetKind::Service);
}

/// The hint is a fixed sentence. Anything interpolated into it would be attacker-controlled bytes
/// in a message rendered before the request has been authenticated.
#[test]
fn n_the_diagnostic_message_repeats_nothing_from_the_request() {
    let message = VhostHint::LooksLikeVhostButNotConfigured.message();
    for fragment in ["conf-host", "other.example.com", "example", "PUT"] {
        assert!(
            !message.contains(fragment),
            "the hint must not repeat `{fragment}`: it is rendered before authentication"
        );
    }
    // Two different requests produce the identical sentence, which is what "fixed" means.
    let one = resolve(&PathStyleOnly, "conf-host.other.example.com", "PUT", "/");
    let two = resolve(&PathStyleOnly, "second-bucket.elsewhere.test", "DELETE", "/");
    assert_eq!(one.diagnostic, two.diagnostic);
}

/// The hint stays silent when it would be wrong: a host that resolved, a path that already names
/// a bucket, a first label no bucket could be called, and a method that is not a bucket write.
#[test]
fn n_the_diagnostic_stays_silent_when_it_would_be_noise() {
    for (host, method, path) in [
        // Resolved as a virtual host: nothing is misconfigured.
        ("conf-host.s3.example.com", "PUT", "/"),
        // The path already names a bucket, so this is a deliberate path-style request.
        ("conf-host.other.example.com", "PUT", "/conf-host"),
        // `s3` is two characters; no bucket can be called that, so the host is not vhost-shaped.
        ("s3.other.example.com", "PUT", "/"),
        // One label: there is no bucket position in front of anything.
        ("localhost", "PUT", "/"),
        // A method that never addresses a bucket root.
        ("conf-host.other.example.com", "POST", "/"),
    ] {
        let resolved = resolve(&two_domains(), host, method, path);
        assert_eq!(resolved.diagnostic, None, "host {host} {method} {path}");
    }
}

/// The bucket comes from the host and the whole path is the key. A path-style reading of the same
/// request would take `bb2` as the bucket, which is the two-sources-of-truth defect the resolver
/// exists to close.
#[test]
fn n_a_virtual_hosted_bucket_is_not_taken_from_the_path() {
    let request = http::Request::builder()
        .method("GET")
        .uri("/bb2/key")
        .header("host", "conf-host.s3.example.com")
        .body(())
        .expect("the fixture request is well formed");
    let accepted = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    let resolved = two_domains().resolve(&HostQuery {
        host: accepted.host(),
        path: accepted.raw_path().as_str(),
        method: accepted.method(),
    });
    let view =
        MetaView::addressed(&accepted, resolved.target, resolved.bucket().cloned()).expect("the request addresses an object");
    assert_eq!(view.bucket().map(rustfs_gateway_types::BucketName::as_str), Some("conf-host"));
    assert_eq!(view.key().map(rustfs_gateway_types::ObjectKey::as_str), Some("bb2/key"));

    // The control: the identical path read path-style names a different bucket and a shorter key.
    let path_style = MetaView::addressed(&accepted, TargetKind::Object, None).expect("the path names an object");
    assert_eq!(path_style.bucket().map(rustfs_gateway_types::BucketName::as_str), Some("bb2"));
    assert_eq!(path_style.key().map(rustfs_gateway_types::ObjectKey::as_str), Some("key"));
}

/// `Addressing` is the one place the answer lives: `origin` is read off it rather than stored
/// beside it, so an audit record cannot say `Path` about a bucket that came from the host.
#[test]
fn n_the_origin_cannot_disagree_with_the_addressing() {
    let vhost = resolve(&two_domains(), "conf-host.s3.example.com", "GET", "/key");
    let path = resolve(&two_domains(), "s3.example.com", "GET", "/conf-host/key");
    assert!(matches!(vhost.addressing, Addressing::VirtualHosted { .. }));
    assert_eq!(vhost.origin(), TargetOrigin::Host);
    assert_eq!(path.addressing, Addressing::Path);
    assert_eq!(path.origin(), TargetOrigin::Path);
}
