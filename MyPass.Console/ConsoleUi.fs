namespace MyPass.Console

open MyPass
open MyPass.Aes
open MyPass.Result.Operators
open MyPass.Reader
open MyPass.Reader.Operators
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
        |> (fun cs -> Array.append Password.availableCharacters cs)
        |> Password.createWithCharacters 15u

    let getSecretPassword () =
        let value = getInput "Do you want to write your own password (Y) or have one generated?"
        if value = "Y" then
            getInput "Please enter your password:"
        else
            getExtraPasswordCharacters ()

    let private getWebsiteUrl () =
        getInput "Please enter the URL of the site"
        |> Url.make

    let private getWebsiteUserName () =
        getInput "Please enter your user name for the site"
        |> Name

    let private makeWebLogin () =
        let url = getWebsiteUrl ()
        let userName = getWebsiteUserName ()
        let pw = getSecretPassword ()
        let secret = Vault.createSecuredSecret pw
        Result.map (fun url -> VaultDomain.makeWebLogin url userName secret) url

    let private makeSecret () =
        getSecretPassword ()
        |> Vault.createSecuredSecret
        |> Secret

    let private makePasswordEntry () =
        let r = getInput "What do you want to store?\n1. Web login.\n2. Secret"
        match r with
        | "1" ->
            makeWebLogin ()
        | "2" ->
            makeSecret ()
            |> Success
        | _ ->
            sprintf "You chose %s, you can only choose 1 or 2" r
            |> InvalidChoice
            |> Failure

    let private createUserInput
        vaultPath
        userName
        masterPassPhrase
        (fileKeyPath,fileKey)
        =
        {
            VaultPath = vaultPath;
            FileKeyPath = fileKeyPath;
            FileKey = fileKey;
            UserName = userName;
            MasterPassPhrase = masterPassPhrase
        }

    let private getUserInputForNewVault () =
        createUserInput
            (getVaultPath ())
            (getUserName ())
            (getMasterPassPhrase ())
            (getDefaultFileKeyPath ())

    let private getUserInputForExistingVault () =
        createUserInput
            (getVaultPath ())
            (getUserName ())
            (getMasterPassPhrase ())
        |> fun f -> Result.map f (getFileKeyPath (new FileSystem ()))

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

    let constructVault
        (fs : IFileSystem)
        (userData : UserData)
        : Result<FailReason, unit> =
        try
            let encryptedVault = Vault.encrypt userData.MasterKey Vault.empty
            match encryptedVault with
            | Failure f -> Failure f
            | Success mgr ->
                fs.File.WriteAllBytes (userData.UserInput.VaultPath, mgr)
                fs.File.WriteAllText ("FileKey.fk", userData.UserInput.FileKey |> FileKey.getKey)
                printfn "Your file key has been created, it is here: %s" <| Path.GetFullPath "FileKey.fk"
                printfn "Please keep this safe, it is required to use the vault."
                |> Success
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    let createNewVault () =
        (makeUserData <-| getUserInputForNewVault) ()
        |> constructVault (new FileSystem ())

    let private loadVault (fs : IFileSystem) (userData : UserData) =
        let manager = fs.File.ReadAllBytes userData.UserInput.VaultPath
        Vault.decrypt userData.MasterKey manager

    let private addAndStore
        (fs : IFileSystem)
        (entry : PasswordEntry)
        (ud : UserData)
        (vault : Vault)
        =
        vault
        |> (Vault.storePassword entry >=> Vault.encrypt ud.MasterKey)
        |> Result.map (fun d -> fs.File.WriteAllBytes(ud.UserInput.VaultPath, d))

    let addSecretToVault (fs : IFileSystem) (userData : UserData) =
        try
            let vault = loadVault fs userData
            let name = getInput "Enter the name for this secret:" |> Name
            let desc = getInput "Enter the description for this secret:" |> Description
            let result =
                Result.map (PasswordEntry.create name desc) (makePasswordEntry ())
                >>= (fun entry -> vault >>= addAndStore fs entry userData)
            match result with
            | Failure f -> printfn "ERROR: %s" <| FailReason.toString f
            | Success _ -> printfn "Secret has been stored"
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()

    let addSecret () =
        constructComponentsFromUserInput
        |> Result.map (addSecretToVault (new FileSystem ()))

    let listAllSecrets (fs : IFileSystem) (userData : UserData) : unit =
        let printSecretData (s : Secret) =
            match s with
            | Secret _ -> ""
            | WebLogin wl -> sprintf "\n%A - %A" wl.Url wl.UserName

        let printEntries vault =
            vault.passwords
            |> Map.toList
            |> List.iter
                (fun (n,e) -> printfn "%A\n%A%A\n---------------\n" n e.Description (printSecretData e.Secret))

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

    let showPasswordToUser (vault : Vault) : Result<FailReason, unit> =
        try
            vault
            |> (fun vault ->
                    let entryName =
                        getInput "Please enter the name of the password you wish to see: "
                        |> Name
                    Vault.getPassword entryName vault)
            |> (=<<) PasswordEntry.decrypt
            |> Result.map givePasswordToUser
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    let printPassword () =
        constructComponentsFromUserInput
        |> (=<<) (loadVault (new FileSystem ()))
        |> (=<<) showPasswordToUser