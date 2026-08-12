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

//! Closed values for conditional and byte-range runtime contracts.
//!
//! Responsible for: typed current and mutation alternatives for the precondition family.
//! NOT responsible for: parsing overlay strings or implementing runtime behavior. Upstream: quirk
//! overlays. Downstream: contract parsing and runtime-contract codegen.

macro_rules! two_value_policy {
    ($name:ident, $current:ident, $mutant:ident) => {
        #[doc = concat!("Typed values for the `", stringify!($name), "` contract.")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            #[doc = concat!("Current value: `", stringify!($current), "`.")]
            $current,
            #[doc = concat!("Mutation alternative: `", stringify!($mutant), "`.")]
            $mutant,
        }
    };
}

two_value_policy!(NotModifiedEtagPolicyValue, IncludeSelected, Omit);
two_value_policy!(CompletionFailureUploadPolicyValue, Retain, Consume);
two_value_policy!(ConditionalRaceOutcomeValue, Conflict, PreconditionFailed);
two_value_policy!(MultiRangePolicyValue, ServeWhole, Reject);
two_value_policy!(ExplicitEndOverflowPolicyValue, Clamp, Unsatisfiable);
two_value_policy!(SuffixRangePolicyValue, Supported, Ignore);
two_value_policy!(OversizeSuffixPolicyValue, ClampToWholePartial, Unsatisfiable);
two_value_policy!(UnsatisfiableActualSizeDetailValue, Include, Omit);
two_value_policy!(PartialChecksumPolicyValue, SuppressWholeObject, IncludeWholeObject);
two_value_policy!(PartNumberOutcomeValue, PartialContent, ServeWhole);
two_value_policy!(InvalidRangePolicyValue, ServeWhole, Reject);
two_value_policy!(IfRangeMissPolicyValue, ServeWhole, ServePartial);
two_value_policy!(IfNoneMatchComparisonStrengthValue, Weak, Strong);
two_value_policy!(BareConditionalEtagPolicyValue, AcceptAndNormalize, Reject);
two_value_policy!(NotModifiedBodyPolicyValue, Suppress, Preserve);
two_value_policy!(NotModifiedFramingPolicyValue, Omit, Preserve);
two_value_policy!(RangeStartBoundValue, AtOrBeyondUnsatisfiable, PastEndOnly);
two_value_policy!(OpenEndedRangePolicyValue, ThroughLast, EmptyAtLast);
two_value_policy!(ReadRangeLengthArithmeticValue, Inclusive, Exclusive);
two_value_policy!(CopyRangeLengthArithmeticValue, Inclusive, Exclusive);
two_value_policy!(RangeRequestedDetailValue, Verbatim, Normalized);
two_value_policy!(PartCountHeaderPolicyValue, IncludeTotal, Omit);
two_value_policy!(RangePartSelectorConflictValue, Reject, PreferPart);
