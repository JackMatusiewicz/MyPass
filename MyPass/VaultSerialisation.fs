namespace MyPass

open Newtonsoft.Json

module VaultSerialisation =

    type AesKeyDto = {
        Key : byte[]
    }

    type SecuredSecretDto = (EncryptedData * AesKeyDto)

    type SecretDto =
        | SecretDto of SecuredSecretDto
        | WebLoginDto of (string * Name * SecuredSecretDto)

    type PasswordEntryDto = {
        SecretDto : SecretDto
        Description : Description
        Name : Name }

    type VaultDto =
        {
            PasswordList : (Name * PasswordEntryDto) list
            History : History
        }

    let private toAesKeyDto (k : AesKey) =
        let key = Aes.copyKeyBytes k
        { AesKeyDto.Key = key }

    let private fromAesKeyDto (k : AesKeyDto) =
        Aes.fromBytes k.Key

    let private fromSecretDto (s : SecretDto) : Result<FailReason, Secret> =
        match s with
        | SecretDto (data, key) ->
            { Data = data; Key = fromAesKeyDto key } |> Secret |> Success
        | WebLoginDto (url, name, (data, key)) ->
            let url = Url.make url
            Result.map
                (fun url ->
                    {
                        UserName = name
                        Url = url
                        SecuredData = { Data = data; Key = fromAesKeyDto key }
                    } |> WebLogin)
                url

    let private toSecretDto (s : Secret) : SecretDto =
        match s with
        | Secret s -> (s.Data, toAesKeyDto s.Key) |> SecretDto
        | WebLogin w ->
            (Url.toString w.Url, w.UserName, (w.SecuredData.Data, toAesKeyDto w.SecuredData.Key))
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
        let vaultDto = JsonConvert.DeserializeObject<VaultDto> (vaultDtoString)

        vaultDto
        |> (fun v -> v.PasswordList)
        |> List.traverse (Tuple.traverse fromEntryDto)
        |> Result.map Map.ofList
        |> Result.map (fun ps -> {Passwords = ps; History = vaultDto.History})

    let serialise (v : Vault) : string =
        v.Passwords
        |> Map.toList
        |> List.map (Tuple.map toEntryDto)
        |> fun ps -> { PasswordList = ps; History = v.History }
        |> JsonConvert.SerializeObject