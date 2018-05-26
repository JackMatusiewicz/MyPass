namespace MyPass

open Newtonsoft.Json

module VaultSerialisation =

    type SecuredSecretDto = (EncryptedData * AesKey)

    type SecretDto =
        | SecretDto of SecuredSecretDto
        | WebLoginDto of (string * Name * SecuredSecretDto)

    type PasswordEntryDto = {
        SecretDto : SecretDto
        Description : Description
        Name : Name }

    type VaultDto = { passwordList : (Name * PasswordEntryDto) list }

    let private fromSecretDto (s : SecretDto) : Result<FailReason, Secret> =
        match s with
        | SecretDto (data, key) ->
            { Data = data; Key = key } |> Secret |> Success
        | WebLoginDto (url, name, (data, key)) ->
            let url = Url.make url
            Result.map
                (fun url ->
                    {
                        UserName = name
                        Url = url
                        SecuredData = { Data = data; Key = key }
                    } |> WebLogin)
                url

    let private toSecretDto (s : Secret) : SecretDto =
        match s with
        | Secret s -> (s.Data, s.Key) |> SecretDto
        | WebLogin w ->
            (Url.toString w.Url, w.UserName, (w.SecuredData.Data, w.SecuredData.Key))
            |> WebLoginDto

    let private toEntryDto (pe : PasswordEntry) : PasswordEntryDto =
        {
            Name = pe.Name
            Description = pe.Description
            SecretDto = toSecretDto pe.Secret
        }

    let private fromEntryDto (pe : PasswordEntryDto) : Result<FailReason, PasswordEntry> =
        Result.map
            (fun secretDto ->
                {
                    Name = pe.Name
                    Description = pe.Description
                    Secret = secretDto })
            (fromSecretDto pe.SecretDto)

    let deserialise (vaultDtoString : string) : Result<FailReason, Vault> =
        JsonConvert.DeserializeObject<VaultDto> (vaultDtoString)
        |> (fun v -> v.passwordList)
        |> List.traverse (Tuple.traverse fromEntryDto)
        |> Result.map Map.ofList
        |> Result.map (fun ps -> {passwords = ps})

    let serialise (v : Vault) : string =
        v.passwords
        |> Map.toList
        |> List.map (Tuple.map toEntryDto)
        |> fun ps -> { passwordList = ps }
        |> JsonConvert.SerializeObject