namespace MyPass

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module SecuredSecret =

    let getEncryptedData (sd : SecuredSecret) : EncryptedData =
        sd.Data

    /// Decrypts the secret that lives inside the SecuredSecret
    let decrypt (sd : SecuredData) : Result<FailReason, string> =
        let encryptedBytes, key =
            match sd with
            | SecuredData.Secret ss ->
                let (EncryptedData data) = ss.Data
                data, ss.Key
            | SecuredData.File sf ->
                let (EncryptedFileData data) = sf.File
                data, sf.Key
        try
            key
            |> Aes.decrypt encryptedBytes
            |> String.fromBytes
            |> Success
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    /// Gets the Sha1Hash of the secret inside the SecuredSecret
    let hash (secret : SecuredData) : Result<FailReason, Sha1Hash> =
        decrypt secret |> Result.map Sha1Hash.make

    let create (password : string) : SecuredSecret =
        let passwordKey = Aes.make ()
        let encryptedPassword =
            password
            |> String.toBytes
            |> fun data -> Aes.encrypt data passwordKey
            |> EncryptedData
        { Data = encryptedPassword; Key = passwordKey }

    /// Creates a SecuredSecret with zeroed data.
    /// Mainly used to replace encrypted data when we want to return the secret to view public details.
    let createDummy () : SecuredSecret =
        {
            Data = (EncryptedData [||])
            Key = Aes.make ()
        }