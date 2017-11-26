namespace MyPass

open Aes
open Password
open Result
open System
open System.IO
open System.Text
open Vault
open Newtonsoft.Json

//replace this with a "user input" struct that contains all things from user we will need (all bar the vault)
type UserData = {
    Vault : Vault
    VaultPath : string
    MasterKey : AesKey
}

module ManagerModes =

    let getVaultPath () =
        printfn "Please enter the full path (including the file and extension) to the vault:"
        Console.ReadLine()

    let getUserName () =
        printfn "Please enter the user name for the vault:"
        Console.ReadLine()

    let getFileKeyPath () =
        printfn "Please enter the full path (including the file and extension) to the file key for this vault:"
        Console.ReadLine()

    let getMasterPassPhrase () =
        printfn "Please enter the master pass phrase for this vault:"
        Console.ReadLine()

    let createNewVault () =
        try
            let pathToVault = getVaultPath ()
            let userName = getUserName ()
            let (FileKey fileKey) = FileKey.generateFileKey ()
            let fileKeyBytes = fileKey |> System.Text.Encoding.UTF8.GetBytes
            let passPhrase = getMasterPassPhrase ()
            let masterKey = Password.createMasterPassword "Version1.0" passPhrase fileKeyBytes userName
            let aes = {Key = masterKey}
            let encryptedVault = Vault.encryptManager aes Vault.empty
            match encryptedVault with
            | Failure f -> printfn "%s" f
            | Success mgr ->
                File.WriteAllBytes (pathToVault, mgr)
                File.WriteAllText ("FileKey.fk", fileKey)
                printfn "Your file key has been created, it is here: %s" <| Path.GetFullPath "FileKey.fk"
                printfn "Please keep this safe, it is required to use the vault."
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()

    let loadVault () =
        let pathToVault = getVaultPath ()
        let userName = getUserName ()
        let fileKeyPath = getFileKeyPath ()
        let fileKeyBytes = File.ReadAllBytes fileKeyPath
        let passPhrase = getMasterPassPhrase ()
        let masterKey = Password.createMasterPassword "Version1.0" passPhrase fileKeyBytes userName
        let aes = {Key = masterKey}
        let manager = File.ReadAllBytes pathToVault
        let encryptedVault = Vault.decryptManager aes manager
        (fun v -> {Vault = v; VaultPath = pathToVault; MasterKey = aes}) <!> encryptedVault

    let getSecretPassword () =
        printfn "Do you want to write your own password (Y) or have one generated?"
        let value = Console.ReadLine()
        if value = "Y" then
            Console.ReadLine()
        else
            Password.createPassword 15u

    let addSecret () =
        try
            let vault = loadVault ()
            printfn "Enter the name for this secret:"
            let name = Console.ReadLine()
            printfn "Enter the description for this secret:"
            let desc = Console.ReadLine()
            let pw = getSecretPassword ()
            let entry = Vault.createEntry (BasicDescription (name, desc)) pw
            let result = vault >>= (fun ud ->
                            ud.Vault |> Vault.storePassword entry
                                     >>= Vault.encryptManager ud.MasterKey
                                     <?> (fun d -> File.WriteAllBytes(ud.VaultPath, d)))
            match result with
            | Failure f -> printfn "ERROR: %s" f
            | Success _ -> printfn "Secret has been stored"
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()
