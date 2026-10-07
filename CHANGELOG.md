# Changelog

## rustfs-gateway-types 0.31.0+aws.2026-10-02

The model snapshot moves to AWS api-models-aws commit `7eb6ab98cd5f1e5dc6dd90ea1bdc625f9ae308ba`.
It adds `IntelligentTieringReferenceDate` to the inventory optional-field model; STS is unchanged.
The public `OptionalFields` open string type recognizes the new value. No operation is enabled
by this update, and storage formats are unchanged.
