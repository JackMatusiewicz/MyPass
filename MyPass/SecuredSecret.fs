namespace MyPass

open System.Text

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module SecuredSecret =

    let getEncryptedData (sd : SecuredSecret) : EncryptedData =
        sd.Data

    let decrypt (sd : SecuredSecret) : Result<FailReason, string> =
        try
            let (EncryptedData encryptedBytes) = sd.Data
            encryptedBytes
            |> Aes.decrypt (sd.Key)
            |> Encoding.UTF8.GetString
            |> Success
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    let create (password : string) : SecuredSecret =
        let passwordKey = Aes.make ()
        let encryptedPassword =
            password
            |> Encoding.UTF8.GetBytes
            |> Aes.encrypt passwordKey
            |> EncryptedData
        { Data = encryptedPassword; Key = passwordKey }