namespace MyPass

open FSharp.Data
open Newtonsoft.Json
open System.Text
open System.Net.Http
open System.Security.Cryptography

open Result.Operators

module Hibp =

    let private client = new HttpClient ()

    let private getHash (secret : SecuredSecret) : Result<FailReason, string> =
        SecuredSecret.decrypt secret
        |> Result.map (fun pw ->
            let pwBytes = Encoding.UTF8.GetBytes(pw : string)
            use sha1 = new SHA1Managed ()

            sha1.ComputeHash (pwBytes)
            |> Array.map (fun (b : byte) -> b.ToString("X2"))
            |> Array.fold (fun (s : StringBuilder) a -> s.Append(a)) (new StringBuilder ())
            |> fun sb -> sb.ToString ())

    let findMatchingHashes (hashPrefix : string) : Result<FailReason, Set<string>> =
        let response =
            async {
                return Http.Request (sprintf "https://api.pwnedpasswords.com/range/%s" hashPrefix)
            } |> Async.RunSynchronously
        match response.StatusCode with
        | 200 ->
            match response.Body with
            | Text data ->
                JsonConvert.DeserializeObject<string[]>(data)
                |> Array.map (fun (d : string) -> (d.Split([|':'|])).[0])
                |> Array.map (fun d -> hashPrefix + d)
                |> Set.ofArray
                |> Success
            | _ -> Failure InvalidResponseFormat
        | sc -> Failure (HttpRequestFailed sc)

    let isCompromised (secret : SecuredSecret) : Result<FailReason, bool> =
        let hash = getHash secret
        Result.map (fun (hash : string) -> hash.[0..4]) hash
        |> (=<<) findMatchingHashes
        |> (=<<) (fun hashes -> hash >>= fun hash -> Success <| Set.contains hash hashes)