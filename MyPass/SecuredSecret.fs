namespace MyPass

open System.Text
open System.Security.Cryptography

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

    /// Gets the hash of the secret inside the SecuredSecret
    let hash (secret : SecuredSecret) : Result<FailReason, string> =
        decrypt secret
        |> Result.map (fun pw ->
            let pwBytes = Encoding.UTF8.GetBytes(pw : string)
            use sha1 = new SHA1Managed ()

            sha1.ComputeHash (pwBytes)
            |> Array.map (fun (b : byte) -> b.ToString("X2"))
            |> Array.fold (fun (s : StringBuilder) a -> s.Append(a)) (new StringBuilder ())
            |> fun sb -> sb.ToString ())

    let create (password : string) : SecuredSecret =
        let passwordKey = Aes.make ()
        let encryptedPassword =
            password
            |> Encoding.UTF8.GetBytes
            |> fun data -> Aes.encrypt data passwordKey
            |> EncryptedData
        { Data = encryptedPassword; Key = passwordKey }