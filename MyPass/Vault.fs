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

    let encrypt
        (key : AesKey)
        (manager : Vault)
        : Result<FailReason, byte[]>
        =
        fun () ->
            manager
            |> VaultSerialisation.serialise
            |> Encoding.UTF8.GetBytes
            |> Aes.encrypt key
            |> Success
        |> exceptionToFailure

    let decrypt
        (key : AesKey)
        (encryptedManager : byte[])
        : Result<FailReason, Vault>
        =
        fun () ->
            encryptedManager
            |> Aes.decrypt key
            |> Encoding.UTF8.GetString
            |> VaultSerialisation.deserialise
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