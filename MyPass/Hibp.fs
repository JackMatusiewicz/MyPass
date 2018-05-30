namespace MyPass

open FSharp.Data
open Newtonsoft.Json
open System.Text
open System.Net.Http
open System.Security.Cryptography

open Result.Operators

/// Represents the JSON string that is returned from the HIBP password query.
type HibpResponse = Response of string

type CompromisedStatus = Compromised | NotCompromised

module Hibp =
    open System.Security
    open System

    let private client = new HttpClient ()

    let findMatchingHashes (hashPrefix : string) : Result<FailReason, HibpResponse> =
        let response =
            async {
                return Http.Request (sprintf "https://api.pwnedpasswords.com/range/%s" hashPrefix)
            } |> Async.RunSynchronously
        match response.StatusCode with
        | 200 ->
            match response.Body with
            | Text data -> data |> Response |> Success
            | _ -> Failure InvalidResponseFormat
        | sc -> Failure (HttpRequestFailed sc)

    let toHashes (hashPrefix : string) (response : HibpResponse) : Set<string> =
        let (Response data) = response
        data.Split ([|"\r\n"|], StringSplitOptions.RemoveEmptyEntries)
        |> Array.map (fun (d : string) -> (d.Split([|':'|])).[0])
        |> Array.map (fun d -> hashPrefix + d)
        |> Set.ofArray

    let isCompromised
        (finder : string -> Result<FailReason, HibpResponse>)
        (secret : SecuredSecret)
        : Result<FailReason, CompromisedStatus>
        =

        let contains hash hashes =
            match Set.contains hash hashes with
            | true -> Compromised
            | false -> NotCompromised

        let hash = SecuredSecret.hash secret
        let hashPrefix = Result.map (fun (hash : string) -> hash.[0..4]) hash

        hashPrefix
        |> (=<<) finder
        |> (fun s -> toHashes <!> hashPrefix <*> s)
        |> (=<<) (fun hashes -> hash >>= fun hash -> Success <| contains hash hashes)