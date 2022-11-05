namespace MyPass

open System
open System.Runtime.ExceptionServices

[<Struct>]
type FailReason =
    | InvalidUrl of Url : string
    | ExceptionThrown of Exception : ExceptionDispatchInfo
    | DuplicateEntry of Key : string
    | EntryNotFound of Entry : string
    | InvalidCommand of Command : string
    | InvalidChoice of Choice : string
    | InvalidResponseFormat
    | HttpRequestFailed of StatusCode : int
    | InvalidHashPrefix
    | InvalidSha1Hash
    | IncorrectKeyLength of Length : (int * int)
    | DuplicateTag of Tag : string
    | UnableToCreateFile of FilePath : string
    | FilterLeadToNoMatch of Regex : string
    | CannotEditUsernameOfSecuredSecret of SecretName : string

[<RequireQualifiedAccess>]
module FailReason =

    let fromException (ex : Exception) : FailReason =
        ExceptionDispatchInfo.Capture ex
        |> ExceptionThrown

    let toString (f : FailReason) =
        match f with
        | InvalidUrl url -> sprintf "%s was an invalid url" url
        | ExceptionThrown exInfo ->
            sprintf "ERROR: %A" (exInfo.SourceException)
        | DuplicateEntry k -> sprintf "%s already exists" k
        | EntryNotFound k -> sprintf "%s was not found" k
        | InvalidCommand c -> sprintf "%s is not a valid MyPass command" c
        | InvalidChoice c -> sprintf "Invalid choice: %s" c
        | InvalidResponseFormat -> "Data was in the wrong format"
        | HttpRequestFailed sc -> sprintf "Received a failure error code: %d" sc
        | InvalidHashPrefix -> "Hash prefix was not valid for the HaveIBeenPwned web service"
        | InvalidSha1Hash -> "The value was an invalid sha1 hash"
        | IncorrectKeyLength (expected, actual) -> sprintf "Expected a key of length %d but got %d" expected actual
        | DuplicateTag tag -> sprintf "Duplicate tag found: %s" tag
        | UnableToCreateFile filePath -> sprintf "Unable to create a file at location: %s" filePath
        | FilterLeadToNoMatch regex -> sprintf "The filter regex lead to no matches: %s" regex