namespace MyPass

open Aes
open Password
open Result
open Reader
open System
open System.IO
open Vault

///These are all the specific pieces of information we require from the user.
type UserInput = {
    VaultPath : string
    FileKeyPath : string
    FileKey : FileKey
    MasterPassPhrase : string
    UserName : string
}

///This structure contains the input data along with the vault.
type UserData = {
    UserInput : UserInput
    MasterKey : AesKey
}

///The console UI.
module ManagerModes =

    let private getVaultPath () =
        printfn "Please enter the full path (including the file and extension) to the vault:"
        Console.ReadLine()

    let private getUserName () =
        printfn "Please enter the user name for the vault:"
        Console.ReadLine()

    let private getFileKeyPath () =
        printfn "Please enter the full path (including the file and extension) to the file key for this vault:"
        let path = Console.ReadLine()
        path, FileKey.read path

    let private getDefaultFileKeyPath () =
        let (FileKey randomName) = FileKey.generateFileKey ()
        randomName + ".fk", FileKey.generateFileKey ()

    let private getMasterPassPhrase () =
        printfn "Please enter the master pass phrase for this vault:"
        Console.ReadLine()

    let private createUserInput vaultPath masterPassPhrase userName (fileKeyPath,fileKey) =
        {VaultPath = vaultPath; FileKeyPath = fileKeyPath;
            FileKey = fileKey; UserName = userName; MasterPassPhrase = masterPassPhrase}

    let private getUserInputForNewVault =
        createUserInput
        |-> getVaultPath
        |~> getMasterPassPhrase
        |~> getUserName
        |~> getDefaultFileKeyPath

    let private getUserInputForExistingVault =
        createUserInput
        |-> getVaultPath
        |~> getMasterPassPhrase
        |~> getUserName
        |~> getFileKeyPath

    let private constructComponents (userInput : UserInput) =
        let fileKeyBytes = FileKey.toBytes userInput.FileKey
        let masterKey = Password.createMasterPassword "Version1.0" userInput.MasterPassPhrase fileKeyBytes userInput.UserName
        {MasterKey = {Key = masterKey}; UserInput = userInput}

    let createNewVault () =
        try
            let userData = (constructComponents |-> getUserInputForNewVault) ()
            let encryptedVault = Vault.encryptManager userData.MasterKey Vault.empty
            match encryptedVault with
            | Failure f -> printfn "%s" f
            | Success mgr ->
                File.WriteAllBytes (userData.UserInput.VaultPath, mgr)
                File.WriteAllText ("FileKey.fk", userData.UserInput.FileKey |> FileKey.getKey)
                printfn "Your file key has been created, it is here: %s" <| Path.GetFullPath "FileKey.fk"
                printfn "Please keep this safe, it is required to use the vault."
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()

    let private loadVault () =
        let userInput = (constructComponents |-> getUserInputForExistingVault) ()
        let manager = File.ReadAllBytes userInput.UserInput.VaultPath
        let encryptedVault = Vault.decryptManager userInput.MasterKey manager
        (fun v -> (v,userInput)) <!> encryptedVault

    let getSecretPassword () =
        printfn "Do you want to write your own password (Y) or have one generated?"
        let value = Console.ReadLine()
        if value = "Y" then
            printfn "Please enter your password:"
            Console.ReadLine()
        else
            Password.createPassword 15u

    let private addAndStore (entry : PasswordEntry) (vault : Vault, ud : UserData) =
        vault
        |> (Vault.storePassword entry >=> Vault.encryptManager ud.MasterKey)
        <?> (fun d -> File.WriteAllBytes(ud.UserInput.VaultPath, d))

    let addSecret () =
        try
            let vault = loadVault ()
            printfn "Enter the name for this secret:"
            let name = Console.ReadLine()
            printfn "Enter the description for this secret:"
            let desc = Console.ReadLine()
            let pw = getSecretPassword ()
            let entry = Vault.createEntry (BasicDescription (name, desc)) pw
            let result = vault >>= addAndStore entry
            match result with
            | Failure f -> printfn "ERROR: %s" f
            | Success _ -> printfn "Secret has been stored"
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()