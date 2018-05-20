namespace MyPass

open Newtonsoft.Json
open System.Text

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
    Url : Url
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

type VaultDto = { passwordList : (Name * PasswordEntry) list }

[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module Vault =

    let empty = { passwords = Map.empty }

    let private fromDto (vDto : VaultDto) =
        vDto.passwordList
        |> Map.ofList
        |> fun ps -> {passwords = ps}

    let private toDto (v : Vault) =
        v.passwords
        |> Map.toList
        |> fun ps -> {passwordList = ps}

    let private exceptionToFailure (f : unit -> Result<FailReason, 'b>) =
        try
            f ()
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    let createSecret (password : string) =
        let passwordKey = Aes.newKey ()
        let encryptedPassword =
            password
            |> Encoding.UTF8.GetBytes
            |> Aes.encrypt passwordKey
            |> EncryptedData
        {Data = encryptedPassword; Key = passwordKey}
        |> Secret

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

    let private getName (entry : PasswordEntry) =
        let (Name name) = entry.Name
        name

    let getSecureData (entry : PasswordEntry) : SecuredSecret =
        match entry.Secret with
        | WebLogin wl -> wl.SecuredData
        | Secret s -> s

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
            Success {passwords = newStore}

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
            Success {passwords = newStore}

    let removePassword
        (name : Name)
        (manager : Vault)
        : Result<FailReason, Vault>
        =
        let store = manager.passwords
        if Map.containsKey name store then
            let updatedStore = Map.remove name store
            Success {passwords = updatedStore}
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
            |> toDto
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
            |> (fun m -> JsonConvert.DeserializeObject<VaultDto>(m))
            |> fromDto
            |> Success
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