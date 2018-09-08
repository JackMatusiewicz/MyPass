namespace MyPass.Console

open MyPass
open MyPass.Aes
open MyPass.Result.Operators
open MyPass.Reader
open MyPass.Reader.Operators
open MyPass.Vault
open System
open System.Security
open System.IO
open System.IO.Abstractions

///These are all the specific pieces of information we require from the user.
type UserInput = {
    VaultPath : string
    FileKeyPath : string
    FileKey : FileKey
    MasterPassPhrase : SecureString
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
        |> (fun cs -> Array.append Password.alphanumericCharacters cs)
        |> Password.createWithCharacters 15u

    let getSecretPassword () =
        let value = getInput "Do you want to write your own password (Y) or have one generated?"
        if value = "Y" || value = "y" then
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
        let secret = SecuredSecret.create pw
        Result.map (fun url -> VaultDomain.makeWebLogin url userName secret) url

    let private makeSecret () =
        getSecretPassword ()
        |> SecuredSecret.create
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
            Password.createMasterKey
                "Version1.0"
                fileKeyBytes
                userInput.UserName
                userInput.MasterPassPhrase
        {MasterKey = masterKey; UserInput = userInput}

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

    let private storeVault (fs : IFileSystem) (ud : UserData) (vault : Vault) =
        Vault.encrypt ud.MasterKey vault
        |> Result.map (fun data -> fs.File.WriteAllBytes (ud.UserInput.VaultPath, data))

    let addSecretToVault (fs : IFileSystem) (userData : UserData) =
        try
            let vault = loadVault fs userData
            let name = getInput "Enter the name for this secret:" |> Name
            let desc = getInput "Enter the description for this secret:" |> Description
            let entry = makePasswordEntry ()
            let result =
                Result.map (PasswordEntry.create name desc) entry
                >>= (fun entry -> Result.bind vault (Vault.storePassword entry))
                |> Result.map (storeVault fs userData)
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
                (fun (n,e) ->
                    printfn "%A\n%A%A\n---------------\n"
                        n
                        e.Description
                        (printSecretData e.Secret))

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

    let getEntryName () =
        getInput "Please enter the name of the password"
        |> Name

    let private showSpecificPassword (name : Name) (vault : Vault) =
        try
            Vault.getPassword name vault
            |> (=<<) PasswordEntry.decrypt
            |> Result.map givePasswordToUser
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    let private getUserEntryChoice (v : Vault) =
        let getUserChoice (max : int) =
            let v =
                sprintf "Please pick a password (0 - %d)" max
                |> getInput
                |> int
            if v >= 0 && v <= max then
                Success v
            else
                sprintf "You must choose between 0-%d" max
                |> InvalidChoice
                |> Failure

        let choices =
            v.passwords
            |> Map.toList
            |> List.map fst
            |> List.mapi (fun i (Name k) -> (i,k))

        List.iter (fun (index, name) -> printfn "%d) %s" index name) choices

        getUserChoice (List.length choices - 1)
        |> Result.map (fun i -> List.item i choices)
        |> Result.map snd

    let showPasswordToUser (v : Vault) =
        getUserEntryChoice v
        |> (=<<) (fun name -> showSpecificPassword (Name name) v)

    let printPassword () =
        constructComponentsFromUserInput
        |> (=<<) (loadVault (new FileSystem ()))
        |> (=<<) showPasswordToUser

    let private changePassword (vault : Vault) : Result<FailReason, Vault> =
        let choice = getUserEntryChoice vault |> Result.map Name

        Result.bind choice (fun n -> showSpecificPassword n vault)
        |> (=<<)
            (fun () ->
                let pw =
                    getSecretPassword ()
                    |> SecuredSecret.create
                Result.bind choice (fun n -> Vault.getPassword n vault)
                |> Result.map (PasswordEntry.updateSecret pw)
                |> (=<<) (fun e -> Vault.updatePassword e vault))
        |> (=<<)
            (fun v ->
                Result.bind choice (fun n -> showSpecificPassword n v)
                |> Result.map (fun _ -> v))

    let updatePassword () =
        let ud = constructComponentsFromUserInput
        let fs = new FileSystem ()
        ud
        |> (=<<) (loadVault fs)
        |> (=<<) changePassword
        |> (=<<) (fun d -> Result.bind ud (fun ud -> storeVault fs ud d))

    let checkForCompromisedPasswords () =
        let ud = constructComponentsFromUserInput
        let fs = new FileSystem ()
        ud
        |> (=<<) (loadVault fs)
        |> (=<<) (Vault.getCompromisedPasswords (Hibp.isCompromised Hibp.checkHashPrefix))
        |> fun data -> printfn "Here are a list of compromised passwords:"; data
        |> Result.map (List.iter (fun (Name n) -> printfn "%s" n))
