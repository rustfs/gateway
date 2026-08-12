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

//! Runtime vocabulary for conditional and byte-range contracts.
//!
//! Responsible for: closed policy types consumed by the precondition pipeline.
//! NOT responsible for: selecting current values or evaluating requests.
//! Upstream: generated contract constants. Downstream: shared precondition logic and adapters.

macro_rules! two_value_policy {
    ($name:ident, $current:ident, $mutant:ident) => {
        #[doc = concat!("Typed values for the `", stringify!($name), "` contract.")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
        pub(crate) enum $name {
            #[doc = concat!("Current value: `", stringify!($current), "`.")]
            $current,
            #[doc = concat!("Mutation alternative: `", stringify!($mutant), "`.")]
            $mutant,
        }
    };
}

two_value_policy!(NotModifiedEtagPolicy, IncludeSelected, Omit);
two_value_policy!(CompletionFailureUploadPolicy, Retain, Consume);
two_value_policy!(ConditionalRaceOutcomePolicy, Conflict, PreconditionFailed);
two_value_policy!(UnsatisfiableActualSizeDetailPolicy, Include, Omit);
two_value_policy!(PartialChecksumPolicy, SuppressWholeObject, IncludeWholeObject);
two_value_policy!(PartNumberOutcomePolicy, PartialContent, ServeWhole);
two_value_policy!(IfRangeMissPolicy, ServeWhole, ServePartial);
two_value_policy!(IfNoneMatchComparisonStrengthPolicy, Weak, Strong);
two_value_policy!(BareConditionalEtagPolicy, AcceptAndNormalize, Reject);
two_value_policy!(NotModifiedBodyPolicy, Suppress, Preserve);
two_value_policy!(NotModifiedFramingPolicy, Omit, Preserve);
two_value_policy!(ReadRangeLengthArithmetic, Inclusive, Exclusive);
two_value_policy!(CopyRangeLengthArithmetic, Inclusive, Exclusive);
two_value_policy!(RangeRequestedDetailPolicy, Verbatim, Normalized);
two_value_policy!(PartCountHeaderPolicy, IncludeTotal, Omit);
two_value_policy!(RangePartSelectorConflictPolicy, Reject, PreferPart);
