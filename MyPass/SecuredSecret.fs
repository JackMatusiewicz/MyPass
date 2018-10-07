namespace MyPass

open System.Text

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
            |> String.fromBytes
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
            |> String.toBytes
            |> fun data -> Aes.encrypt data passwordKey
            |> EncryptedData
        { Data = encryptedPassword; Key = passwordKey }