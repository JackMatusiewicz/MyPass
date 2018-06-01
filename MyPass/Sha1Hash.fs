namespace MyPass

open System.Text
open System.Text.RegularExpressions
open System.Security.Cryptography

/// Stores the hexadecimal representation of the SHA1 hash of some data.
type Sha1Hash = private Hash of string

module Sha1Hash =

    let private sha1Regex = Regex("^[a-fA-F0-9]{40}$")

    let make (s : string) : Sha1Hash =
        let pwBytes = Encoding.UTF8.GetBytes(s : string)
        use sha1 = new SHA1Managed ()

        sha1.ComputeHash (pwBytes)
        |> Array.map (fun (b : byte) -> b.ToString("X2"))
        |> Array.fold (fun (s : StringBuilder) a -> s.Append(a)) (new StringBuilder ())
        |> fun sb -> sb.ToString ()
        |> Hash

    /// Converts a Hex string into a Sha1Hash
    let fromString (data : string) =
        let m = sha1Regex.Match (data)
        match m.Success with
        | true -> Hash data |> Success
        | _ -> Failure InvalidSha1Hash

    let get ((Hash h) : Sha1Hash) : string = h