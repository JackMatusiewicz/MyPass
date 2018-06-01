namespace MyPass

/// Represents the first 5 characters of a hash, used in HaveIBeenPwned.
type HashPrefix = private Prefix of string

module HashPrefix =

    let make (s : string) : Result<FailReason, HashPrefix> =
        match s.Length with
        | 5 -> Prefix s |> Success
        | _ -> Failure InvalidHashPrefix

    let prefix (Prefix s) = s