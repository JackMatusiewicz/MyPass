namespace MyPass

open Aes
open Result
open Newtonsoft.Json
open System.Text

type Url = string
type DescriptionText = string
type Name = string

type Description = BasicDescription of Name * DescriptionText
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

    let createEntry (desc : Description) (password : string) =
        let passwordKey = Aes.newKey ()
        let passwordBytes = Encoding.UTF8.GetBytes(password)
        let encryptedPassword = EncryptedPassword (Aes.encrypt passwordKey passwordBytes)
        {Password = encryptedPassword; Key = passwordKey; Description = desc }

    let private getName (description : Description) =
        match description with
        | BasicDescription (name,_) -> name
        | FullDescription (name,_,_) -> name

    let storePassword (entry : PasswordEntry) (manager : Vault)
        : Result<string, Vault> =
        let store = manager.passwords
        let name = getName (entry.Description)
        if Map.containsKey name store then
            Failure "Password entry already exists"
        else
            let newStore = Map.add name entry store
            Success <| {passwords = newStore}

    let updatePassword (entry : PasswordEntry) (manager : Vault)
        : Result<string, Vault> =
        let store = manager.passwords
        let name = getName (entry.Description)
        if Map.containsKey name store = false then
            Failure "Password entry does not exist"
        else
            let newStore = Map.add name entry store
            Success <| {passwords = newStore}

    let removePassword (name : Name) (manager : Vault)
        : Result<string, Vault> =
        let store = manager.passwords
        if Map.containsKey name store then
            let updatedStore = Map.remove name store
            Success <| {passwords = updatedStore}
        else
            Failure "Password entry did not exist under that name."

    let encryptManager (key : AesKey) (manager : Vault) : Result<string, byte[]> =
        try
            let managerAsJson = JsonConvert.SerializeObject(manager)
            Success <| (Aes.encrypt key <| Encoding.UTF8.GetBytes(managerAsJson))
        with
         ex -> Failure ex.Message

    let decryptManager (key : AesKey) (encryptedManager : byte[])
        : Result<string, Vault> =
        try
            let managerAsBytes = Aes.decrypt key encryptedManager
            let managerAsString = Encoding.UTF8.GetString(managerAsBytes)
            Success <| JsonConvert.DeserializeObject<Vault>(managerAsString)
        with
           ex -> Failure ex.Message

    let getPassword (name : Name) (manager : Vault)
        : Result<string, PasswordEntry> =
        let store = manager.passwords
        if Map.containsKey name store then
            Success <| Map.find name store
        else
            Failure "Unable to find a password matching that name."

    let decryptPassword (entry : PasswordEntry) : Result<string, string> =
        try
            let (EncryptedPassword encryptedBytes) = entry.Password
            let decryptedPassword = Aes.decrypt (entry.Key) (encryptedBytes)
            Success <| Encoding.UTF8.GetString(decryptedPassword)
        with
            ex -> Failure ex.Message