namespace MyPass


[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module PasswordEntry =

    let getSecureData (entry : PasswordEntry) : SecuredData =
        match entry.Secret with
        | WebLogin wl -> SecuredData.Secret wl.SecuredData
        | Secret s -> SecuredData.Secret s
        | EncryptedFile ef -> File ef

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
        VaultDomain.updateSecret newSecret entry.Secret
        |> Result.map (fun newSecret -> { entry with Secret = newSecret })

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