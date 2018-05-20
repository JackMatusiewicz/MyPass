namespace MyPass

open Newtonsoft.Json

module VaultDto =

    type SecuredSecretDto = (EncryptedData * AesKey)

    type SecretDto =
        | SecretDto of SecuredSecretDto
        | WebLoginDto of (Url * Name * SecuredSecretDto)

    type PasswordEntryDto = {
        SecretDto : SecretDto
        Description : Description
        Name : Name }

    type VaultDto = { passwordList : (Name * PasswordEntryDto) list }

    let private fromSecretDto (s : SecretDto) : Secret =
        match s with
        | SecretDto (data, key) ->
            { Data = data; Key = key } |> Secret
        | WebLoginDto (url, name, (data, key)) ->
            {
                UserName = name
                Url = url
                SecuredData = { Data = data; Key = key }
            } |> WebLogin

    let private toSecretDto (s : Secret) : SecretDto =
        match s with
        | Secret s -> (s.Data, s.Key) |> SecretDto
        | WebLogin w ->
            (w.Url, w.UserName, (w.SecuredData.Data, w.SecuredData.Key))
            |> WebLoginDto

    let private toEntryDto (pe : PasswordEntry) : PasswordEntryDto =
        {
            Name = pe.Name
            Description = pe.Description
            SecretDto = toSecretDto pe.Secret
        }

    let private fromEntryDto (pe : PasswordEntryDto) : PasswordEntry =
        {
            Name = pe.Name
            Description = pe.Description
            Secret = fromSecretDto pe.SecretDto
        }

    let fromDto (vaultDtoString : string) =
        JsonConvert.DeserializeObject<VaultDto> (vaultDtoString)
        |> (fun v -> v.passwordList)
        |> List.map (Tuple.map fromEntryDto)
        |> Map.ofList
        |> fun ps -> {passwords = ps}

    let toDto (v : Vault) =
        v.passwords
        |> Map.toList
        |> List.map (Tuple.map toEntryDto)
        |> fun ps -> { passwordList = ps }