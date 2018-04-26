namespace MyPass

open Aes
open Newtonsoft.Json
open System.Text

type Url = string
type DescriptionText = string
type Name = string

type Description =
    | BasicDescription of Name * DescriptionText
    | FullDescription of Name * Url * DescriptionText

type EncryptedPassword = EncryptedPassword of byte[]

type PasswordEntry = {
    Password : EncryptedPassword
    Key : AesKey
    Description : Description
}

type Vault = {
    passwords : Map<Name, PasswordEntry>
}

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module Vault =

    let empty = { passwords = Map.empty }

    let private exceptionToFailure (f : unit -> Result<string, 'b>) =
        try
            f ()
        with
        | ex -> ex.Message |> Failure

    let createEntry (desc : Description) (password : string) =
        let passwordKey = Aes.newKey ()
        let encryptedPassword =
            password
            |> Encoding.UTF8.GetBytes
            |> Aes.encrypt passwordKey
            |> EncryptedPassword
        {Password = encryptedPassword; Key = passwordKey; Description = desc }

    let private getName (description : Description) =
        match description with
        | BasicDescription (name,_) -> name
        | FullDescription (name,_,_) -> name

    let storePassword (entry : PasswordEntry) (manager : Vault) : Result<string, Vault> =
        let store = manager.passwords
        let name = getName (entry.Description)
        if Map.containsKey name store then
            Failure "Password entry already exists"
        else
            let newStore = Map.add name entry store
            Success {passwords = newStore}

    let updatePassword (entry : PasswordEntry) (manager : Vault) : Result<string, Vault> =
        let store = manager.passwords
        let name = getName (entry.Description)
        if Map.containsKey name store = false then
            Failure "Password entry does not exist"
        else
            let newStore = Map.add name entry store
            Success {passwords = newStore}

    let removePassword (name : Name) (manager : Vault) : Result<string, Vault> =
        let store = manager.passwords
        if Map.containsKey name store then
            let updatedStore = Map.remove name store
            Success {passwords = updatedStore}
        else
            Failure "Password entry did not exist under that name."

    let encryptManager (key : AesKey) (manager : Vault) : Result<string, byte[]> =
        fun () ->
            manager
            |> JsonConvert.SerializeObject
            |> Encoding.UTF8.GetBytes
            |> Aes.encrypt key
            |> Success
        |> exceptionToFailure

    let decryptManager (key : AesKey) (encryptedManager : byte[]) : Result<string, Vault> =
        fun () ->
            encryptedManager
            |> Aes.decrypt key
            |> Encoding.UTF8.GetString
            |> (fun m -> JsonConvert.DeserializeObject<Vault>(m))
            |> Success
        |> exceptionToFailure

    let getPassword (name : Name) (manager : Vault) : Result<string, PasswordEntry> =
        let store = manager.passwords
        if Map.containsKey name store then
            Success <| Map.find name store
        else
            Failure "Unable to find a password matching that name."

    let decryptPassword (entry : PasswordEntry) : Result<string, string> =
        fun () ->
            let (EncryptedPassword encryptedBytes) = entry.Password
            encryptedBytes
            |> Aes.decrypt (entry.Key)
            |> Encoding.UTF8.GetString
            |> Success
        |> exceptionToFailure
