namespace MyPass

[<RequireQualifiedAccess>]
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
                [Tag.password]

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

    let addTag (tag : Tag) (entry : PasswordEntry) : Result<FailReason, PasswordEntry> =
        match Set.contains tag entry.Tags with
        | true ->
            Tag.toString tag
            |> DuplicateTag
            |> Failure
        | false ->
            { entry with
                Tags = Set.add tag entry.Tags
            } |> Success

    let updateDescription (description : Description) (entry : PasswordEntry) : PasswordEntry =
        { entry with Description = description }

    let updateWebLoginUsername (username : Name) (entry : PasswordEntry) : Result<FailReason, PasswordEntry> =
        match entry.Secret with
        | WebLogin login ->
            let updatedLogin = { login with UserName = username }
            { entry with Secret = WebLogin updatedLogin }
            |> Success
        | Secret _ ->
            entry.Name
            |> Name.toString
            |> CannotEditUsernameOfSecuredSecret
            |> Failure