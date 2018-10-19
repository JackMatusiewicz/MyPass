namespace MyPass

open System.Text

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module PasswordEntry =

    let getSecureData (entry : PasswordEntry) : SecuredSecret =
        match entry.Secret with
        | WebLogin wl -> wl.SecuredData
        | Secret s -> s

    let decrypt (entry : PasswordEntry) : Result<FailReason, string> =
        getSecureData entry
        |> SecuredSecret.decrypt

    let create
        (name : Name)
        (desc : Description)
        (secret : Secret)
        =
        let tags =
            match secret with
            | Secret _ -> []
            | WebLogin w ->
                [Tag.fromString "password"]

        {
            Name = name
            Description = desc
            Secret = secret
            Tags = Set.ofList tags
        }

    let updateSecret
        (newSecret : SecuredSecret)
        (entry : PasswordEntry)
        =
        let newSecret = VaultDomain.updateSecret newSecret entry.Secret
        { entry with Secret = newSecret }