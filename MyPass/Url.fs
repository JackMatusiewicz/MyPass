﻿namespace MyPass

open System

[<Struct>]
type Url = private Url of string

[<RequireQualifiedAccess>]
module Url =

    let make (s : string) : Result<FailReason, Url> =
        match Uri.IsWellFormedUriString (s, UriKind.Absolute) with
        | true ->
            s |> Url |> Success
        | false ->
            sprintf "%s is not a valid url" s
            |> InvalidUrl
            |> Failure

    let toString ((Url v) : Url) = v
