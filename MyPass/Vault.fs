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

    /// Takes a new password entry and replaces another entry with the same key.
    /// Will fail if there is no entry with the provided name of the new entry.
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

    /// Removes a secret that has the provided name.
    /// Will fail if there is no secret with the provided name.
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

    /// Encrypts a vault with the provided AES key.
    let encrypt
        (key : AesKey)
        (manager : Vault)
        : Result<FailReason, byte[]>
        =
        fun () ->
            manager
            |> VaultSerialisation.serialise
            |> Encoding.UTF8.GetBytes
            |> fun data -> Aes.encrypt data key
            |> Success
        |> exceptionToFailure

    /// Decrypts a vault with the provided key.
    let decrypt
        (key : AesKey)
        (encryptedManager : byte[])
        : Result<FailReason, Vault>
        =
        fun () ->
            encryptedManager
            |> fun data -> Aes.decrypt data key
            |> Encoding.UTF8.GetString
            |> VaultSerialisation.deserialise
        |> exceptionToFailure

    /// Gets the password entry for the provided name.
    /// Will fail if no entry exists.
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

    /// Finds all of the compromised entries in the vault.
    let getCompromisedPasswords
        (isCompromised : SecuredSecret -> Result<FailReason, CompromisedStatus>)
        (vault : Vault)
        : Result<FailReason, Name list>
        =
        vault.passwords
        |> Map.toArray
        |> Array.map (Tuple.map PasswordEntry.getSecureData)
        |> Array.Parallel.map (Tuple.map isCompromised)
        |> Array.toList
        |> List.traverse (Tuple.sequence)
        |> Result.map (List.filter (fun (a,b) -> b = Compromised))
        |> Result.map (List.map fst)