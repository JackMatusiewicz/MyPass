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

module ConsoleUi =

    let private getInput (question : string) =
        printfn "%s" question
        Console.ReadLine()

    let private getVaultPath () =
        getInput "Please enter the full path (including the file and extension) to the vault:"

    let private getUserName () =
        getInput "Please enter the user name for the vault:"

    let private getFileKeyPath () =
        let path =
            getInput "Please enter the full path (including the file and extension) to the file key for this vault:"
        path, FileKey.read path

    let private getDefaultFileKeyPath () =
        let (FileKey randomName) = FileKey.generateFileKey ()
        randomName + ".fk", FileKey.generateFileKey ()

    let private getMasterPassPhrase () =
        printfn "Please enter the master pass phrase for this vault:"
        SecureInput.get ()

    let private createUserInput vaultPath masterPassPhrase userName (fileKeyPath,fileKey) =
        {VaultPath = vaultPath; FileKeyPath = fileKeyPath;
            FileKey = fileKey; UserName = userName; MasterPassPhrase = masterPassPhrase}

    let private getUserInputForNewVault =
        createUserInput
            <-| getVaultPath
            <~| getMasterPassPhrase
            <~| getUserName
            <~| getDefaultFileKeyPath

    let private getUserInputForExistingVault =
        createUserInput
            <-| getVaultPath
            <~| getMasterPassPhrase
            <~| getUserName
            <~| getFileKeyPath

    let private constructComponents (userInput : UserInput) =
        let fileKeyBytes = FileKey.toBytes userInput.FileKey
        let masterKey =
            Password.createMasterPassword
                "Version1.0"
                userInput.MasterPassPhrase
                fileKeyBytes
                userInput.UserName
        {MasterKey = {Key = masterKey}; UserInput = userInput}

    let constructVault (userData : UserData) =
        try
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

    let createNewVault () =
        (constructComponents <-| getUserInputForNewVault) ()
        |> constructVault

    let private loadVault (userData : UserData) =
        let manager = File.ReadAllBytes userData.UserInput.VaultPath
        Vault.decryptManager userData.MasterKey manager

    let getSecretPassword () =
        let value = getInput "Do you want to write your own password (Y) or have one generated?"
        if value = "Y" then
            getInput "Please enter your password:"
        else
            Password.createPassword 15u

    let private addAndStore (entry : PasswordEntry) (ud : UserData) (vault : Vault) =
        vault
        |> (Vault.storePassword entry >=> Vault.encryptManager ud.MasterKey)
        |> Result.map (fun d -> File.WriteAllBytes(ud.UserInput.VaultPath, d))

    let addSecretToVault (userData : UserData) =
        try
            let vault = loadVault userData
            let name = getInput "Enter the name for this secret:"
            let desc = getInput "Enter the description for this secret:"
            let pw = getSecretPassword ()
            let entry = Vault.createEntry (BasicDescription (name, desc)) pw
            let result = vault >>= addAndStore entry userData
            match result with
            | Failure f -> printfn "ERROR: %s" f
            | Success _ -> printfn "Secret has been stored"
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()

    let addSecret () =
        (constructComponents <-| getUserInputForExistingVault) ()
        |> addSecretToVault

    let listAllSecrets (userData : UserData) : unit =
        let printEntries vault =
            vault.passwords
            |> Map.toList
            |> List.map snd
            |> List.iter (fun e -> printfn "%A\n---------------\n" e.Description)

        try
            loadVault (userData)
            |> Result.iter printEntries
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()

    let listSecrets () =
        (constructComponents <-| getUserInputForExistingVault) ()
        |> listAllSecrets

    let private givePasswordToUser (password : string) =
        printfn "Your password will be in your clipboard for 15 seconds."
        Clipboard.timedStoreInClipboard 15000 password
        printfn "Your password has been removed from your clipboard"

    let showPasswordToUser (userData : UserData) : unit =
        try
            loadVault (userData)
            |> (=<<)
                (fun vault ->
                    let entryName = getInput "Please enter the name of the password you wish to see: "
                    Vault.getPassword entryName vault)
            |> (=<<) Vault.decryptPassword
            |> Result.iter givePasswordToUser
            |> ignore
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()

    let printPassword () =
        (constructComponents <-| getUserInputForExistingVault) ()
        |> showPasswordToUser