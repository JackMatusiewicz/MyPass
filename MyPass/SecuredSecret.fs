namespace MyPass

open System.Text
open System.Security.Cryptography

//TODO - move to a new file
/// Stores the hexadecimal representation of the SHA1 hash of some data.
type Sha1Hash = private Hash of string

module Sha1Hash =

    let make (s : string) : Sha1Hash =
        let pwBytes = Encoding.UTF8.GetBytes(s : string)
        use sha1 = new SHA1Managed ()

        sha1.ComputeHash (pwBytes)
        |> Array.map (fun (b : byte) -> b.ToString("X2"))
        |> Array.fold (fun (s : StringBuilder) a -> s.Append(a)) (new StringBuilder ())
        |> fun sb -> sb.ToString ()
        |> Hash

    // TODO - replace with something that checks if a string is a valid SHA1 hash.
    let internal fromString (data : string) = Hash data

    let get ((Hash h) : Sha1Hash) : string = h

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module SecuredSecret =

    let getEncryptedData (sd : SecuredSecret) : EncryptedData =
        sd.Data

    /// Decrypts the secret that lives inside the SecuredSecret
    let decrypt (sd : SecuredSecret) : Result<FailReason, string> =
        try
            let (EncryptedData encryptedBytes) = sd.Data

            sd.Key
            |> Aes.decrypt encryptedBytes
            |> Encoding.UTF8.GetString
            |> Success
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    /// Gets the Sha1Hash of the secret inside the SecuredSecret
    let hash (secret : SecuredSecret) : Result<FailReason, Sha1Hash> =
        decrypt secret |> Result.map (Sha1Hash.make)

    let create (password : string) : SecuredSecret =
        let passwordKey = Aes.make ()
        let encryptedPassword =
            password
            |> Encoding.UTF8.GetBytes
            |> fun data -> Aes.encrypt data passwordKey
            |> EncryptedData
        { Data = encryptedPassword; Key = passwordKey }