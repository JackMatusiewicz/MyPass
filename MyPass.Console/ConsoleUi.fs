namespace MyPass.Console

open MyPass
open MyPass.Clipboard
open MyPass.Result.Operators
open MyPass.Reader.Operators
open System
open System.Security
open System.IO
open System.IO.Abstractions
open MyPass.SecureString

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

    let private generatePassword () =
        let value = getInput "Would you like a random password (Y) or a memorable password?"
        if value = "y" || value = "Y" then
            getInput "Please enter the extra characters to use for password generation:"
            |> fun s -> s.ToCharArray ()
            |> (fun cs -> Array.append Password.alphanumericCharacters cs)
            |> (fun cs -> getInput "Please enter the number of characters for the password:", cs)
            |> Tuple.lmap uint32
            |> (<||) Password.createWithCharacters
        else
            getInput "Please enter the minimum number of characters for the password:"
            |> uint32
            |> Password.createMemorablePassword

    let getSecretPassword () =
        let value = getInput "Do you want to write your own password (Y) or have one generated?"
        if value = "Y" || value = "y" then
            printfn "Please enter your password:"
            SecureInput.get ()
        else
            generatePassword ()

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
        let secret = SecurePasswordHandler.Use(pw, fun p -> p |> String.fromBytes |> SecuredSecret.create)
        Result.map (fun url -> VaultDomain.makeWebLogin url userName secret) url

    let private makeSecret () =
        getSecretPassword ()
        |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes |> SecuredSecret.create)
        |> Secret

    let printTags (tags : Set<Tag>) =
        let data = Set.toList tags
        match data with
        | [] -> ()
        | _ ->
            data
            |> List.map Tag.toString
            |> List.reduce (sprintf "%s,%s")
            |> printfn "Tags: %s"


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
            MasterKey.make
                "Version1.0"
                fileKeyBytes
                userInput.UserName
                userInput.MasterPassPhrase
        {MasterKey = masterKey; UserInput = userInput}

    let private constructComponentsFromUserInput =
        getUserInputForExistingVault ()
        |> (Result.map makeUserData)

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
            v.Passwords
            |> Map.toList
            |> List.map fst
            |> List.mapi (fun i (Name k) -> (i,k))

        List.iter (fun (index, name) -> printfn "%d) %s" index name) choices

        getUserChoice (List.length choices - 1)
        |> Result.map (fun i -> List.item i choices)
        |> Result.map snd
        |> Result.map (fun c -> printfn "You have chosen: %s" c; c)

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
                >>= (fun entry -> Result.bind vault (Vault.storePassword Time.get entry))
                |> Result.map (storeVault fs userData)
            match result with
            | Failure f -> printfn "ERROR: %s" <| FailReason.toString f
            | Success _ -> printfn "Secret has been stored"
        with
        | ex -> printfn "ERROR: %s" <| ex.ToString()

    let addSecret () =
        constructComponentsFromUserInput
        |> Result.map (addSecretToVault (new FileSystem ()))

    let printDetail () : Result<FailReason, unit> =
        let printEntryDetails (entry : PasswordEntry) =
            printfn "--------------------------------------"
            printfn "Entry name: %s" <| Name.toString entry.Name
            printfn "Description: %s" <| Description.toString entry.Description
            printTags entry.Tags
            match entry.Secret with
            | Secret _ -> ()
            | WebLogin wl ->
                printfn "Username: %s" <| Name.toString wl.UserName
                printfn "URL: %s" <| Url.toString wl.Url
            printfn "--------------------------------------"

        let fs = new FileSystem ()
        let ud = constructComponentsFromUserInput
        let vault = ud >>= loadVault (fs)
        let entryName = vault >>= getUserEntryChoice
        Result.bind2 entryName vault (fun en v -> Vault.getPublicEntryDetails Time.get (Name en) v)
        |> Result.map (Tuple.lmap printEntryDetails)
        |> Result.map snd
        |> fun v -> Result.bind2 ud v (storeVault fs)

    let private givePasswordToUser (password : string) =
        printfn "Your password will be in your clipboard for 15 seconds."
        Clipboard.timedStore 15000 password
        printfn "Your password has been removed from your clipboard"

    let getEntryName () =
        getInput "Please enter the name of the password"
        |> Name

    let private showSpecificPassword (name : Name) (vault : Vault) : Result<FailReason, Vault> =
        try
            let res = Vault.getPassword Time.get name vault

            (res |> Result.map fst)
            >>= PasswordEntry.decrypt
            |> Result.map givePasswordToUser |> ignore

            Result.map snd res
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    let showPasswordToUser (v : Vault) =
        getUserEntryChoice v
        >>= (fun name -> showSpecificPassword (Name name) v)

    let printPassword () : Result<FailReason, unit> =
        let fs = new FileSystem ()
        let ud = constructComponentsFromUserInput
        let vault = ud >>= loadVault (fs)
        let updatedVault = vault >>= showPasswordToUser
        Result.bind2 ud updatedVault (storeVault fs)

    let private changePassword (vault : Vault) : Result<FailReason, Vault> =
        let choice = getUserEntryChoice vault |> Result.map Name

        Result.bind choice (fun n -> showSpecificPassword n vault)
        >>=
            (fun v ->
                let pw =
                    getSecretPassword ()
                    |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes |> SecuredSecret.create)
                Result.bind choice (fun n -> Vault.getPassword Time.get n v)
                |> Result.map (Tuple.lmap (PasswordEntry.updateSecret pw)))
        >>= ((<||) (Vault.updatePassword Time.get))
        >>=
            (fun v ->
                Result.bind choice (fun n -> showSpecificPassword n v))

    let updatePassword () =
        let ud = constructComponentsFromUserInput
        let fs = new FileSystem ()
        ud
        >>= loadVault fs
        >>= changePassword
        >>= (fun d -> Result.bind ud (fun ud -> storeVault fs ud d))

    let private removePw (vault : Vault) : Result<FailReason, Vault> =
        getUserEntryChoice vault
        |> Result.map Name
        >>= (fun name -> Vault.removePassword Time.get name vault)

    //TODO - there is lots of boilerplate duplication, refactor this!
    let removePassword () =
        let ud = constructComponentsFromUserInput
        let fs = new FileSystem ()
        ud
        >>= loadVault fs
        >>= removePw
        >>= (fun d -> Result.bind ud (fun ud -> storeVault fs ud d))

    let checkForCompromisedPasswords () =
        let ud = constructComponentsFromUserInput
        let fs = new FileSystem ()
        ud
        >>= loadVault fs
        >>= (Vault.getCompromisedPasswords Time.get (Hibp.isCompromised Hibp.checkHashPrefix))
        |> fun data -> printfn "Here are a list of compromised passwords:"; data
        |> Result.map
            (fun (data, vault) ->
                List.iter (Name.toString >> printfn "%s") data
                vault)
        |> fun v -> Result.bind2 ud v (storeVault fs)

    let showDuplicatePasswords () =
        let ud = constructComponentsFromUserInput
        let fs = new FileSystem ()
        ud
        >>= loadVault fs
        >>= Vault.findReusedSecrets Time.get
        >>= (fun (secrets, vault) ->
                secrets
                |> fun d -> printfn "Here are groups of duplicate passwords:"; d
                |> List.map (List.map (Name.toString))
                |> List.map (List.reduce (fun acc n -> sprintf "%s, %s" n acc))
                |> List.iteri (fun i n -> printfn "%d) %s" i n)
                Result.lift vault)
        |> fun v -> Result.bind2 ud v (storeVault fs)

    let printHistory () =
        let ud = constructComponentsFromUserInput
        let fs = new FileSystem ()

        ud
        >>= loadVault fs
        |> Result.map (fun v -> v.History)
        |> Result.map AppendOnlyRingBuffer.get
        |> Result.map (Array.map UserActivity.toString)
        |> Result.map (Array.iter (printfn "%s"))