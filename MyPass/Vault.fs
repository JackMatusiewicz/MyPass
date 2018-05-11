namespace MyPass

open Aes
open Newtonsoft.Json
open System.Text

[<Struct>]
type Url2 = Url2 of string

[<Struct>]
type Description = Description of string

[<Struct>]
type Name = Name of string

[<Struct>]
type EncryptedData = EncryptedData of byte[]

type SecuredSecret = {
    Data : EncryptedData
    Key : AesKey }

type WebLogin = {
    SecuredData : SecuredSecret
    Url : Url2
    UserName : Name }

[<Struct>]
type Secret =
    | Secret of Secret : SecuredSecret
    | WebLogin of Login : WebLogin

type PasswordEntry = {
    Secret : Secret
    Description : Description
    Name : Name
}

type Vault = { passwords : Map<Name, PasswordEntry> }

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module Vault =

    let empty = { passwords = Map.empty }

    let private exceptionToFailure (f : unit -> Result<string, 'b>) =
        try
            f ()
        with
        | ex -> ex.Message |> Failure

    let createSecret (password : string) =
        let passwordKey = Aes.newKey ()
        let encryptedPassword =
            password
            |> Encoding.UTF8.GetBytes
            |> Aes.encrypt passwordKey
            |> EncryptedData
        {Data = encryptedPassword; Key = passwordKey}
        |> Secret

    let createEntry (name : Name) (desc : Description) (secret : Secret) =
        {
            Name = name
            Description = desc
            Secret = secret
        }

    let private getName (entry : PasswordEntry) =
        let (Name name) = entry.Name
        name

    let getSecureData (entry : PasswordEntry) : SecuredSecret =
        match entry.Secret with
        | WebLogin wl -> wl.SecuredData
        | Secret s -> s

    let storePassword (entry : PasswordEntry) (manager : Vault) : Result<string, Vault> =
        let store = manager.passwords
        let name = entry.Name
        if Map.containsKey name store then
            Failure "Password entry already exists"
        else
            let newStore = Map.add name entry store
            Success {passwords = newStore}

    let updatePassword (entry : PasswordEntry) (manager : Vault) : Result<string, Vault> =
        let store = manager.passwords
        let name = entry.Name
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
            let secureData = getSecureData entry
            let (EncryptedData encryptedBytes) = secureData.Data

            encryptedBytes
            |> Aes.decrypt (secureData.Key)
            |> Encoding.UTF8.GetString
            |> Success
        |> exceptionToFailure