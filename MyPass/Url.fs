namespace MyPass

open System

[<Struct>]
type Url = private Url of string

module Url =

    let make (s : string) : Result<FailReason, Url> =
        match Uri.IsWellFormedUriString (s, UriKind.RelativeOrAbsolute) with
        | true ->
            s |> Url |> Success
        | false ->
            sprintf "%s is not a valid url" s
            |> InvalidUrl
            |> Failure

    ///This should only be used when we know it is a url.
    let internal ensure (s : string) : Url =
        match Uri.IsWellFormedUriString (s, UriKind.RelativeOrAbsolute) with
        | true ->
            s |> Url
        | false -> failwith "Invalid URL - this should never happen!"

    let toString ((Url v) : Url) = v
