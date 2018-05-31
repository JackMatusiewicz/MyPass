namespace MyPass

open FSharp.Data
open Newtonsoft.Json
open System.Text
open System.Net.Http
open System.Security.Cryptography

open Result.Operators

type CompromisedStatus = Compromised | NotCompromised

type HashPrefix = private Prefix of string

//TODO - move this to its own file.
module HashPrefix =

    let make (s : string) : Result<FailReason, HashPrefix> =
        match s.Length with
        | 5 -> Prefix s |> Success
        | _ -> Failure InvalidHashPrefix

    let prefix (Prefix s) = s


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

    let toHashes (response : HibpResponse) : Set<Sha1Hash> =
        let (Response ((Prefix hashPrefix), suffixData)) = response
        suffixData.Split ([|"\r\n"|], StringSplitOptions.RemoveEmptyEntries)
        |> Array.map (fun (d : string) -> (d.Split([|':'|])).[0])
        |> Array.map (fun d -> hashPrefix + d)
        |> Array.map Sha1Hash.fromString
        |> Set.ofArray

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
        |> (fun response -> toHashes <!> response)
        |> (=<<) (fun hashes -> hash >>= fun hash -> Success <| contains hash hashes)