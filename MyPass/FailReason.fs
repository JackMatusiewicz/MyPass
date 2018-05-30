﻿namespace MyPass

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

module FailReason =

    let fromException (ex : Exception) : FailReason =
        ExceptionDispatchInfo.Capture ex
        |> ExceptionThrown

    let toString (f : FailReason) =
        match f with
        | InvalidUrl url -> sprintf "%s was an invalid url" url
        | ExceptionThrown exInfo ->
            sprintf "ERROR: %s" (exInfo.SourceException.StackTrace)
        | DuplicateEntry k -> sprintf "%s already exists" k
        | EntryNotFound k -> sprintf "%s was not found" k
        | InvalidCommand c -> sprintf "%s is not a valid MyPass command" c
        | InvalidChoice c -> sprintf "Invalid choice: %s" c
        | InvalidResponseFormat -> "Data was in the wrong format"
        | HttpRequestFailed sc -> sprintf "Received a failure error code: %d" sc