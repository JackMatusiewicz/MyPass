namespace MyPass

open Aes
open Password
open Result
open System
open System.IO
open System.Text
open Vault
open Newtonsoft.Json

module ManagerModes =

    //TODO - rewrite all of these modes.
    let getMasterKey () =
        printfn "Please enter your username: "
        let username = Console.ReadLine()
        printfn "Please enter your password: "
        let password = Console.ReadLine()
        Aes.generateFromPassPhrase (Salt username) (PassPhrase password)

    let exportManagerToFile (key : AesKey) (path : string) (manager : Vault) =
        let storeJson = JsonConvert.SerializeObject(manager)
        let encryptedBytes = Aes.encrypt key <| Encoding.UTF8.GetBytes(storeJson)
        File.WriteAllBytes(path, encryptedBytes)

    let createPasswordStore () =
        printfn "Please enter the directory to place the store: "
        let path = Console.ReadLine()
        try
            let fullPath = Path.GetFullPath path
            let masterKey = getMasterKey ()
            let emptyStore = {passwords = Map.empty}
            exportManagerToFile masterKey (Path.Combine(path, "store.kps")) emptyStore
            Success <| sprintf "Created a keystore at %s" (Path.Combine(path, "store.kps"))
        with
            ex -> Failure ex.Message

    let addPassword () =
        printfn "Please enter path to the MyPass store: "
        let path = Console.ReadLine()
        try
            let fullPath = Path.GetFullPath path
            let masterKey = getMasterKey ()
            let encryptedBytes = File.ReadAllBytes(fullPath)
            let decryptedBytes = Aes.decrypt masterKey encryptedBytes
            let decryptedJson = Encoding.UTF8.GetString(decryptedBytes)
            let vault = JsonConvert.DeserializeObject<Vault>(decryptedJson)

            printfn "Enter the name for the password"
            let passwordName = Console.ReadLine().ToLower()
            printfn "Enter a description"
            let description = Console.ReadLine()
            let genericPw = Password.createPassword 10u //TODO - make this customisable
            let passwordEntry = Vault.createEntry (BasicDescription (passwordName, description)) genericPw
            let updatedManager = Vault.storePassword passwordEntry vault
            map (exportManagerToFile masterKey fullPath) updatedManager |> ignore
            Success <| sprintf "Successfully added password."
        with
            ex -> Failure ex.Message

    let showAllPasswords () =
        printfn "Please enter path to the MyPass store: "
        let path = Console.ReadLine()
        try
            let fullPath = Path.GetFullPath path
            let masterKey = getMasterKey ()
            let encryptedBytes = File.ReadAllBytes(fullPath)
            let decryptedBytes = Aes.decrypt masterKey encryptedBytes
            let decryptedJson = Encoding.UTF8.GetString(decryptedBytes)
            let vault = JsonConvert.DeserializeObject<Vault>(decryptedJson)
            vault.passwords |> Map.toList |> List.map snd |> List.iter (fun entry ->
                printfn "%A : %A" entry.Description (Vault.decryptPassword entry)
            )
            Success <| sprintf "Successfully showed passwords."
        with
            ex -> Failure ex.Message

    let showPassword () =
        printfn "Please enter path to the MyPass store: "
        let path = Console.ReadLine()
        try
            let fullPath = Path.GetFullPath path
            let masterKey = getMasterKey ()
            let encryptedBytes = File.ReadAllBytes(fullPath)
            let decryptedBytes = Aes.decrypt masterKey encryptedBytes
            let decryptedJson = Encoding.UTF8.GetString(decryptedBytes)
            printfn "Enter the name for the password"
            let passwordName = Console.ReadLine().ToLower()
            let vault = JsonConvert.DeserializeObject<Vault>(decryptedJson)
            if Map.containsKey passwordName vault.passwords then
                let pwEntry = Map.find passwordName vault.passwords
                printfn "%A" (Vault.decryptPassword pwEntry)
                Success <| sprintf "Successfully showed password."
            else
                Failure "Password is not present."
        with
            ex -> Failure ex.Message