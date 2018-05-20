namespace MyPass

open Newtonsoft.Json
open System.Text

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module Vault =

    let empty = { passwords = Map.empty }

    let private exceptionToFailure (f : unit -> Result<FailReason, 'b>) =
        try
            f ()
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    let getSecureData (entry : PasswordEntry) : SecuredSecret =
        match entry.Secret with
        | WebLogin wl -> wl.SecuredData
        | Secret s -> s

    let getEncryptedData (sd : SecuredSecret) : EncryptedData =
        sd.Data

    //TODO - move this out
    let createSecuredSecret (password : string) : SecuredSecret =
        let passwordKey = Aes.newKey ()
        let encryptedPassword =
            password
            |> Encoding.UTF8.GetBytes
            |> Aes.encrypt passwordKey
            |> EncryptedData
        { Data = encryptedPassword; Key = passwordKey }

    //TODO - move this out
    let createSecret = createSecuredSecret >> Secret

    let createEntry
        (name : Name)
        (desc : Description)
        (secret : Secret)
        =
        {
            Name = name
            Description = desc
            Secret = secret
        }

    let storePassword
        (entry : PasswordEntry)
        (manager : Vault)
        : Result<FailReason, Vault>
        =
        let store = manager.passwords
        let name = entry.Name
        if Map.containsKey name store then
            DuplicateEntry "Password entry already exists"
            |> Failure
        else
            let newStore = Map.add name entry store
            Success { passwords = newStore }

    let updatePassword
        (entry : PasswordEntry)
        (manager : Vault)
        : Result<FailReason, Vault>
        =
        let store = manager.passwords
        let name = entry.Name
        if Map.containsKey name store = false then
            EntryNotFound "Password entry not found"
            |> Failure
        else
            let newStore = Map.add name entry store
            Success { passwords = newStore }

    let removePassword
        (name : Name)
        (manager : Vault)
        : Result<FailReason, Vault>
        =
        let store = manager.passwords
        if Map.containsKey name store then
            let updatedStore = Map.remove name store
            Success { passwords = updatedStore }
        else
            EntryNotFound "Password entry not found"
            |> Failure

    let encryptManager
        (key : AesKey)
        (manager : Vault)
        : Result<FailReason, byte[]>
        =
        fun () ->
            manager
            |> VaultDto.toDto
            |> JsonConvert.SerializeObject
            |> Encoding.UTF8.GetBytes
            |> Aes.encrypt key
            |> Success
        |> exceptionToFailure

    let decryptManager
        (key : AesKey)
        (encryptedManager : byte[])
        : Result<FailReason, Vault>
        =
        fun () ->
            encryptedManager
            |> Aes.decrypt key
            |> Encoding.UTF8.GetString
            |> VaultDto.fromDto
        |> exceptionToFailure

    let getPassword
        (name : Name)
        (manager : Vault)
        : Result<FailReason, PasswordEntry>
        =
        let store = manager.passwords
        if Map.containsKey name store then
            Success <| Map.find name store
        else
            EntryNotFound "Unable to find a password matching that name."
            |> Failure

    let decryptPassword (entry : PasswordEntry) : Result<FailReason, string> =
        fun () ->
            let secureData = getSecureData entry
            let (EncryptedData encryptedBytes) = secureData.Data

            encryptedBytes
            |> Aes.decrypt (secureData.Key)
            |> Encoding.UTF8.GetString
            |> Success
        |> exceptionToFailure