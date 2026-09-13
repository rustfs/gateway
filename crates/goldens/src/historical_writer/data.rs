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

//! Byte-exact historical-writer fixture bindings.
//! Responsible for: linking digest-named raw exports into the historical matrix.
//! NOT responsible for: synthesizing XML or deciding whether a parser accepts it.
//! Upstream: six stopped synthetic writers. Downstream: the historical corpus validator.

pub(super) const BLOBS: &[(&str, &[u8])] = &[
    (
        "22b785fb6cc215e7d3e82981301fa6b8207d577f9b4210b4dc9ed27c3cc05365",
        include_bytes!("../../corpus/historical-writers/22b785fb6cc215e7d3e82981301fa6b8207d577f9b4210b4dc9ed27c3cc05365.xml"),
    ),
    (
        "288153fe0cab43fab3b7f0a29aa6ed852482b13c5e9184c120023fee02587228",
        include_bytes!("../../corpus/historical-writers/288153fe0cab43fab3b7f0a29aa6ed852482b13c5e9184c120023fee02587228.xml"),
    ),
    (
        "2d168d5a2c974d774ae7056919f574192e9a84db5e119aa728f80b058f4b724c",
        include_bytes!("../../corpus/historical-writers/2d168d5a2c974d774ae7056919f574192e9a84db5e119aa728f80b058f4b724c.xml"),
    ),
    (
        "33e72fe18d08a9dd2192bb3bab5cf5ba70e224409c2ef17069221f2091241549",
        include_bytes!("../../corpus/historical-writers/33e72fe18d08a9dd2192bb3bab5cf5ba70e224409c2ef17069221f2091241549.xml"),
    ),
    (
        "3be21775e812a918e38a43271cc35ebec41a9c2d3abcfb3e2127273394c09ee3",
        include_bytes!("../../corpus/historical-writers/3be21775e812a918e38a43271cc35ebec41a9c2d3abcfb3e2127273394c09ee3.xml"),
    ),
    (
        "3d0ed9e1ec83360f4f238e6aced5b578f74d3f6204ba799f0cf1ba8ef45be8c2",
        include_bytes!("../../corpus/historical-writers/3d0ed9e1ec83360f4f238e6aced5b578f74d3f6204ba799f0cf1ba8ef45be8c2.xml"),
    ),
    (
        "43a157b5cb1e971572f03dd17e3a0aaf75849747285da4211d62fffee25a6811",
        include_bytes!("../../corpus/historical-writers/43a157b5cb1e971572f03dd17e3a0aaf75849747285da4211d62fffee25a6811.xml"),
    ),
    (
        "482d4e510b5cdcf0bbf3a044e82832dc711f4f28757a6c06eb21758282a73ef7",
        include_bytes!("../../corpus/historical-writers/482d4e510b5cdcf0bbf3a044e82832dc711f4f28757a6c06eb21758282a73ef7.xml"),
    ),
    (
        "680ef234c55f9669cb8b38257e63bfbe8f03eb5a28ad05e10b83284f31a8c426",
        include_bytes!("../../corpus/historical-writers/680ef234c55f9669cb8b38257e63bfbe8f03eb5a28ad05e10b83284f31a8c426.xml"),
    ),
    (
        "6d5c2f6a54aadc3c4dcd45125407741ddb75dd16c546300ee2890fd82d28ffdf",
        include_bytes!("../../corpus/historical-writers/6d5c2f6a54aadc3c4dcd45125407741ddb75dd16c546300ee2890fd82d28ffdf.xml"),
    ),
    (
        "92b4a963bcb40c73a3d0a7c98e05bb2b12e415eebc3be06f62deda20fa575654",
        include_bytes!("../../corpus/historical-writers/92b4a963bcb40c73a3d0a7c98e05bb2b12e415eebc3be06f62deda20fa575654.xml"),
    ),
    (
        "93a81818390c6a2e1da0b03ebd2c7c30a21d130f523e85f3c837e122aa73f588",
        include_bytes!("../../corpus/historical-writers/93a81818390c6a2e1da0b03ebd2c7c30a21d130f523e85f3c837e122aa73f588.xml"),
    ),
    (
        "9e0cd496864d37d21cea1f238d8329b5bdada9685cf4e80f8851836c9ce0b5f6",
        include_bytes!("../../corpus/historical-writers/9e0cd496864d37d21cea1f238d8329b5bdada9685cf4e80f8851836c9ce0b5f6.xml"),
    ),
    (
        "a55fd1558c0333de028bb2a684c121aa0a8bda4ea5aaf1a919decef21ab936b4",
        include_bytes!("../../corpus/historical-writers/a55fd1558c0333de028bb2a684c121aa0a8bda4ea5aaf1a919decef21ab936b4.xml"),
    ),
    (
        "a5bbc9d845819231484305e127bff6277434f524723b63cd93287daaac397c75",
        include_bytes!("../../corpus/historical-writers/a5bbc9d845819231484305e127bff6277434f524723b63cd93287daaac397c75.xml"),
    ),
    (
        "ad7548b40a234cff37c87235f803eb6b5f9a8344583c5c2f3b6c1059724aba8f",
        include_bytes!("../../corpus/historical-writers/ad7548b40a234cff37c87235f803eb6b5f9a8344583c5c2f3b6c1059724aba8f.xml"),
    ),
    (
        "bc47f59ba53d878589ee258c22e9c7dbac872ae100a106cd540bbefbdfdaf73e",
        include_bytes!("../../corpus/historical-writers/bc47f59ba53d878589ee258c22e9c7dbac872ae100a106cd540bbefbdfdaf73e.xml"),
    ),
    (
        "c4b4d348ce048b627ab1dc9df2654647d8182e11ee74fbeded579e2f77c7c4bc",
        include_bytes!("../../corpus/historical-writers/c4b4d348ce048b627ab1dc9df2654647d8182e11ee74fbeded579e2f77c7c4bc.xml"),
    ),
    (
        "cb25c2ddabf60344b313e1d624f813d858043ed815bd9a1088ff170ad1c73e14",
        include_bytes!("../../corpus/historical-writers/cb25c2ddabf60344b313e1d624f813d858043ed815bd9a1088ff170ad1c73e14.xml"),
    ),
    (
        "cb55d1d74144c5f9f50b3e22a249af0ddd47788c96474b0c341770f1e2d28419",
        include_bytes!("../../corpus/historical-writers/cb55d1d74144c5f9f50b3e22a249af0ddd47788c96474b0c341770f1e2d28419.xml"),
    ),
    (
        "d9a3beeef24b5bb185c1789d6946ebfd624eb30dd96b117226a2ca2578dc4121",
        include_bytes!("../../corpus/historical-writers/d9a3beeef24b5bb185c1789d6946ebfd624eb30dd96b117226a2ca2578dc4121.xml"),
    ),
    (
        "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a",
        include_bytes!("../../corpus/historical-writers/dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a.xml"),
    ),
    (
        "df4e3e6cf7a0b4af67ba58f41eaa596d54579eea2ed2f993da09600f59413711",
        include_bytes!("../../corpus/historical-writers/df4e3e6cf7a0b4af67ba58f41eaa596d54579eea2ed2f993da09600f59413711.xml"),
    ),
    (
        "e26d01d6339c6ad0d55c3eb24d130c46d85b023b20bdcfffce12605948caa8b4",
        include_bytes!("../../corpus/historical-writers/e26d01d6339c6ad0d55c3eb24d130c46d85b023b20bdcfffce12605948caa8b4.xml"),
    ),
    (
        "e82a38c89506f435da57c8a5318810e7f5e6efaebe33087c7b35348ee8ac6a4e",
        include_bytes!("../../corpus/historical-writers/e82a38c89506f435da57c8a5318810e7f5e6efaebe33087c7b35348ee8ac6a4e.xml"),
    ),
    (
        "ec080c03da956816ea7320adf9ddea32d387d2fa006d4f32d294ccdb816d565f",
        include_bytes!("../../corpus/historical-writers/ec080c03da956816ea7320adf9ddea32d387d2fa006d4f32d294ccdb816d565f.xml"),
    ),
    (
        "f6eee243c53f25e8c1bdc2205f07fbcd9f180379db1afddd1940c55aa2177be3",
        include_bytes!("../../corpus/historical-writers/f6eee243c53f25e8c1bdc2205f07fbcd9f180379db1afddd1940c55aa2177be3.xml"),
    ),
    (
        "86588f7c6cc85b6d1487cb3245e76b89656c8ca445e933668559f8dad8466d11",
        include_bytes!("../../corpus/historical-writers/86588f7c6cc85b6d1487cb3245e76b89656c8ca445e933668559f8dad8466d11.xml"),
    ),
];

use crate::provenance::{PersistenceSource, SourceRegistration};

pub(crate) const REGISTRATIONS: [SourceRegistration; 6] = [
    SourceRegistration {
        source: PersistenceSource::HistoricalWriterMatrix,
        writer: Some("rustfs"),
        version: Some("1.0.0-alpha.64"),
        witness_digests: &[
            "3be21775e812a918e38a43271cc35ebec41a9c2d3abcfb3e2127273394c09ee3",
            "3d0ed9e1ec83360f4f238e6aced5b578f74d3f6204ba799f0cf1ba8ef45be8c2",
            "680ef234c55f9669cb8b38257e63bfbe8f03eb5a28ad05e10b83284f31a8c426",
            "a55fd1558c0333de028bb2a684c121aa0a8bda4ea5aaf1a919decef21ab936b4",
            "cb55d1d74144c5f9f50b3e22a249af0ddd47788c96474b0c341770f1e2d28419",
            "d9a3beeef24b5bb185c1789d6946ebfd624eb30dd96b117226a2ca2578dc4121",
            "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a",
        ],
        reference: "crates/goldens/corpus/historical-writers/manifest.json#rustfs-alpha64",
    },
    SourceRegistration {
        source: PersistenceSource::HistoricalWriterMatrix,
        writer: Some("rustfs"),
        version: Some("1.0.0-alpha.94"),
        witness_digests: &[
            "22b785fb6cc215e7d3e82981301fa6b8207d577f9b4210b4dc9ed27c3cc05365",
            "3be21775e812a918e38a43271cc35ebec41a9c2d3abcfb3e2127273394c09ee3",
            "3d0ed9e1ec83360f4f238e6aced5b578f74d3f6204ba799f0cf1ba8ef45be8c2",
            "43a157b5cb1e971572f03dd17e3a0aaf75849747285da4211d62fffee25a6811",
            "680ef234c55f9669cb8b38257e63bfbe8f03eb5a28ad05e10b83284f31a8c426",
            "92b4a963bcb40c73a3d0a7c98e05bb2b12e415eebc3be06f62deda20fa575654",
            "a5bbc9d845819231484305e127bff6277434f524723b63cd93287daaac397c75",
            "ad7548b40a234cff37c87235f803eb6b5f9a8344583c5c2f3b6c1059724aba8f",
            "bc47f59ba53d878589ee258c22e9c7dbac872ae100a106cd540bbefbdfdaf73e",
            "c4b4d348ce048b627ab1dc9df2654647d8182e11ee74fbeded579e2f77c7c4bc",
            "cb55d1d74144c5f9f50b3e22a249af0ddd47788c96474b0c341770f1e2d28419",
            "d9a3beeef24b5bb185c1789d6946ebfd624eb30dd96b117226a2ca2578dc4121",
            "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a",
        ],
        reference: "crates/goldens/corpus/historical-writers/manifest.json#rustfs-alpha94",
    },
    SourceRegistration {
        source: PersistenceSource::HistoricalWriterMatrix,
        writer: Some("rustfs"),
        version: Some("v1.0.0-beta.1"),
        witness_digests: &[
            "22b785fb6cc215e7d3e82981301fa6b8207d577f9b4210b4dc9ed27c3cc05365",
            "3be21775e812a918e38a43271cc35ebec41a9c2d3abcfb3e2127273394c09ee3",
            "3d0ed9e1ec83360f4f238e6aced5b578f74d3f6204ba799f0cf1ba8ef45be8c2",
            "a5bbc9d845819231484305e127bff6277434f524723b63cd93287daaac397c75",
            "ad7548b40a234cff37c87235f803eb6b5f9a8344583c5c2f3b6c1059724aba8f",
            "bc47f59ba53d878589ee258c22e9c7dbac872ae100a106cd540bbefbdfdaf73e",
            "c4b4d348ce048b627ab1dc9df2654647d8182e11ee74fbeded579e2f77c7c4bc",
            "cb55d1d74144c5f9f50b3e22a249af0ddd47788c96474b0c341770f1e2d28419",
            "d9a3beeef24b5bb185c1789d6946ebfd624eb30dd96b117226a2ca2578dc4121",
            "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a",
            "e26d01d6339c6ad0d55c3eb24d130c46d85b023b20bdcfffce12605948caa8b4",
            "f6eee243c53f25e8c1bdc2205f07fbcd9f180379db1afddd1940c55aa2177be3",
        ],
        reference: "crates/goldens/corpus/historical-writers/manifest.json#rustfs-beta1",
    },
    SourceRegistration {
        source: PersistenceSource::HistoricalWriterMatrix,
        writer: Some("minio"),
        version: Some("RELEASE.2025-09-07T16-13-09Z"),
        witness_digests: &[
            "2d168d5a2c974d774ae7056919f574192e9a84db5e119aa728f80b058f4b724c",
            "33e72fe18d08a9dd2192bb3bab5cf5ba70e224409c2ef17069221f2091241549",
            "482d4e510b5cdcf0bbf3a044e82832dc711f4f28757a6c06eb21758282a73ef7",
            "6d5c2f6a54aadc3c4dcd45125407741ddb75dd16c546300ee2890fd82d28ffdf",
            "df4e3e6cf7a0b4af67ba58f41eaa596d54579eea2ed2f993da09600f59413711",
            "e82a38c89506f435da57c8a5318810e7f5e6efaebe33087c7b35348ee8ac6a4e",
            "ec080c03da956816ea7320adf9ddea32d387d2fa006d4f32d294ccdb816d565f",
        ],
        reference: "crates/goldens/corpus/historical-writers/manifest.json#minio-sept7",
    },
    SourceRegistration {
        source: PersistenceSource::HistoricalWriterMatrix,
        writer: Some("rustfs"),
        version: Some("1.0.0-beta.12"),
        witness_digests: &[
            "22b785fb6cc215e7d3e82981301fa6b8207d577f9b4210b4dc9ed27c3cc05365",
            "3be21775e812a918e38a43271cc35ebec41a9c2d3abcfb3e2127273394c09ee3",
            "3d0ed9e1ec83360f4f238e6aced5b578f74d3f6204ba799f0cf1ba8ef45be8c2",
            "9e0cd496864d37d21cea1f238d8329b5bdada9685cf4e80f8851836c9ce0b5f6",
            "a5bbc9d845819231484305e127bff6277434f524723b63cd93287daaac397c75",
            "ad7548b40a234cff37c87235f803eb6b5f9a8344583c5c2f3b6c1059724aba8f",
            "bc47f59ba53d878589ee258c22e9c7dbac872ae100a106cd540bbefbdfdaf73e",
            "c4b4d348ce048b627ab1dc9df2654647d8182e11ee74fbeded579e2f77c7c4bc",
            "cb25c2ddabf60344b313e1d624f813d858043ed815bd9a1088ff170ad1c73e14",
            "cb55d1d74144c5f9f50b3e22a249af0ddd47788c96474b0c341770f1e2d28419",
            "d9a3beeef24b5bb185c1789d6946ebfd624eb30dd96b117226a2ca2578dc4121",
            "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a",
        ],
        reference: "crates/goldens/corpus/historical-writers/manifest.json#rustfs-beta12",
    },
    SourceRegistration {
        source: PersistenceSource::HistoricalWriterMatrix,
        writer: Some("minio"),
        version: Some("RELEASE.2025-04-22T22-12-26Z"),
        witness_digests: &[
            "86588f7c6cc85b6d1487cb3245e76b89656c8ca445e933668559f8dad8466d11",
            "288153fe0cab43fab3b7f0a29aa6ed852482b13c5e9184c120023fee02587228",
            "33e72fe18d08a9dd2192bb3bab5cf5ba70e224409c2ef17069221f2091241549",
            "3d0ed9e1ec83360f4f238e6aced5b578f74d3f6204ba799f0cf1ba8ef45be8c2",
            "482d4e510b5cdcf0bbf3a044e82832dc711f4f28757a6c06eb21758282a73ef7",
            "93a81818390c6a2e1da0b03ebd2c7c30a21d130f523e85f3c837e122aa73f588",
            "df4e3e6cf7a0b4af67ba58f41eaa596d54579eea2ed2f993da09600f59413711",
            "e82a38c89506f435da57c8a5318810e7f5e6efaebe33087c7b35348ee8ac6a4e",
        ],
        reference: "crates/goldens/corpus/historical-writers/manifest.json#minio-apr22",
    },
];
