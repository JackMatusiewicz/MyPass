namespace MyPass

open System.Text

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module SecuredSecret =

    let getEncryptedData (sd : SecuredSecret) : EncryptedData =
        sd.Data

    let create (password : string) : SecuredSecret =
        let passwordKey = Aes.make ()
        let encryptedPassword =
            password
            |> Encoding.UTF8.GetBytes
            |> Aes.encrypt passwordKey
            |> EncryptedData
        { Data = encryptedPassword; Key = passwordKey }