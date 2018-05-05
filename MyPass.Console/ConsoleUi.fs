namespace MyPass.Console

open MyPass
open MyPass.Aes
open MyPass.Password
open MyPass.Result
open MyPass.Reader
open MyPass.Vault
open System
open System.IO
open System.IO.Abstractions

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

    let private getFileKeyPath (fs : IFileSystem) =
        fun () ->
            let path =
                getInput "Please enter the full path (including the file and extension) to the file key for this vault:"
            FileKey.read fs path
            |> Result.map (fun key -> path,key)

    let private getDefaultFileKeyPath () =
        let (FileKey randomName) = FileKey.generateFileKey ()
        randomName + ".fk", FileKey.generateFileKey ()

    let private getMasterPassPhrase () =
        printfn "Please enter the master pass phrase for this vault:"
        SecureInput.get ()

    let private getExtraPasswordCharacters () =
        getInput "Please enter the extra characters to use for password generation:"
        |> fun s -> s.ToCharArray ()
        |> Password.createWithCharacters 15u

    let private createUserInput
        vaultPath
        masterPassPhrase
        userName
        (fileKeyPath,fileKey)
        =
        {
            VaultPath = vaultPath;
            FileKeyPath = fileKeyPath;
            FileKey = fileKey;
            UserName = userName;
            MasterPassPhrase = masterPassPhrase
        }

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
        |> Reader.applyWithResult (getFileKeyPath (new FileSystem ()))

    let makeUserData (userInput : UserInput) =
        let fileKeyBytes = FileKey.toBytes userInput.FileKey
        let masterKey =
            Password.createMasterPassword
                "Version1.0"
                userInput.MasterPassPhrase
                fileKeyBytes
                userInput.UserName
        {MasterKey = {Key = masterKey}; UserInput = userInput}

    let private constructComponentsFromUserInput =
        getUserInputForExistingVault ()
        |> (Result.map makeUserData)

    let constructVault (fs : IFileSystem) (userData : UserData) : Result<string, unit> =
        try
            let encryptedVault = Vault.encryptManager userData.MasterKey Vault.empty
            match encryptedVault with
            | Failure f -> Failure f
            | Success mgr ->
                fs.File.WriteAllBytes (userData.UserInput.VaultPath, mgr)
                fs.File.WriteAllText ("FileKey.fk", userData.UserInput.FileKey |> FileKey.getKey)
                printfn "Your file key has been created, it is here: %s" <| Path.GetFullPath "FileKey.fk"
                printfn "Please keep this safe, it is required to use the vault."
                |> Success
        with
        | ex -> ex.Message |> Failure

    let createNewVault () =
        (makeUserData <-| getUserInputForNewVault) ()
        |> constructVault (new FileSystem ())

    let private loadVault (fs : IFileSystem) (userData : UserData) =
        let manager = fs.File.ReadAllBytes userData.UserInput.VaultPath
        Vault.decryptManager userData.MasterKey manager

    let getSecretPassword () =
        let value = getInput "Do you want to write your own password (Y) or have one generated?"
        if value = "Y" then
            getInput "Please enter your password:"
        else
            getExtraPasswordCharacters ()

    let private addAndStore
        (fs : IFileSystem)
        (entry : PasswordEntry)
        (ud : UserData)
        (vault : Vault)
        =
        vault
        |> (Vault.storePassword entry >=> Vault.encryptManager ud.MasterKey)
        |> Result.map (fun d -> fs.File.WriteAllBytes(ud.UserInput.VaultPath, d))

    let addSecretToVault (fs : IFileSystem) (userData : UserData) =
        try
            let vault = loadVault fs userData
            let name = getInput "Enter the name for this secret:"
            let desc = getInput "Enter the description for this secret:"
            let pw = getSecretPassword ()
            let entry = Vault.createEntry (BasicDescription (name, desc)) pw
            let result = vault >>= addAndStore fs entry userData
            match result with
            | Failure f -> printfn "ERROR: %s" f
            | Success _ -> printfn "Secret has been stored"
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()

    let addSecret () =
        constructComponentsFromUserInput
        |> Result.map (addSecretToVault (new FileSystem ()))

    let listAllSecrets (fs : IFileSystem) (userData : UserData) : unit =
        let printEntries vault =
            vault.passwords
            |> Map.toList
            |> List.map snd
            |> List.iter (fun e -> printfn "%A\n---------------\n" e.Description)

        try
            loadVault fs userData
            |> Result.iter printEntries
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()

    let listSecrets () =
        constructComponentsFromUserInput
        |> Result.map (listAllSecrets (new FileSystem ()))

    let private givePasswordToUser (password : string) =
        printfn "Your password will be in your clipboard for 15 seconds."
        Clipboard.timedStoreInClipboard 15000 password
        printfn "Your password has been removed from your clipboard"

    let showPasswordToUser (vault : Vault) : Result<string, unit> =
        try
            vault
            |> (fun vault ->
                    let entryName =
                        getInput "Please enter the name of the password you wish to see: "
                    Vault.getPassword entryName vault)
            |> (=<<) Vault.decryptPassword
            |> Result.map givePasswordToUser
        with
        | ex -> ex.Message |> Failure

    let printPassword () =
        constructComponentsFromUserInput
        |> (=<<) (loadVault (new FileSystem ()))
        |> (=<<) showPasswordToUser