namespace MyPass

open System.Text

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module PasswordEntry =

    let getSecureData (entry : PasswordEntry) : SecuredSecret =
        match entry.Secret with
        | WebLogin wl -> wl.SecuredData
        | Secret s -> s

    let decrypt (entry : PasswordEntry) : Result<FailReason, string> =
        try
            let secureData = getSecureData entry
            let (EncryptedData encryptedBytes) = secureData.Data

            encryptedBytes
            |> Aes.decrypt (secureData.Key)
            |> Encoding.UTF8.GetString
            |> Success
        with
        | ex -> FailReason.fromException ex |> Failure

    let create
        (name : Name)
        (desc : Description)
        (secret : Secret)
        =
        {
            Name = name
            Description = desc
            Secret = secret
        }