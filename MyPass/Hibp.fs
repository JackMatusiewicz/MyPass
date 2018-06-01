namespace MyPass

open FSharp.Data
open Newtonsoft.Json
open System.Text
open System.Net.Http
open System.Security.Cryptography

open Result.Operators

type CompromisedStatus = Compromised | NotCompromised

/// Represents the JSON string that is returned from the HIBP password query.
type HibpResponse = Response of (HashPrefix * string)

module Hibp =
    open System.Security
    open System

    let private client = new HttpClient ()

    let checkHashPrefix (hashPrefix : HashPrefix) : Result<FailReason, HibpResponse> =
        let (Prefix hashString) = hashPrefix
        let response =
            async {
                return Http.Request (sprintf "https://api.pwnedpasswords.com/range/%s" hashString)
            } |> Async.RunSynchronously
        match response.StatusCode with
        | 200 ->
            match response.Body with
            | Text data -> data |> fun d -> Response (hashPrefix, d) |> Success
            | _ -> Failure InvalidResponseFormat
        | sc -> Failure (HttpRequestFailed sc)

    let toHashes (response : HibpResponse) : Result<FailReason, Set<Sha1Hash>> =
        let (Response ((Prefix hashPrefix), suffixData)) = response
        suffixData.Split ([|"\r\n"|], StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList
        |> List.map (fun (d : string) -> (d.Split([|':'|])).[0])
        |> List.map (fun d -> hashPrefix + d)
        |> List.traverse Sha1Hash.fromString
        |> Result.map (Set.ofList)

    let isCompromised
        (finder : HashPrefix -> Result<FailReason, HibpResponse>)
        (secret : SecuredSecret)
        : Result<FailReason, CompromisedStatus>
        =
        let contains hash hashes =
            match Set.contains hash hashes with
            | true -> Compromised
            | false -> NotCompromised

        let hash = SecuredSecret.hash secret
        let hashString = Result.map Sha1Hash.get hash
        let hashPrefix =
            Result.map (fun (hash : string) -> hash.[0..4]) hashString
            |> (=<<) HashPrefix.make

        hashPrefix
        |> (=<<) finder
        |> (=<<) toHashes
        |> (=<<) (fun hashes -> hash >>= fun hash -> Success <| contains hash hashes)