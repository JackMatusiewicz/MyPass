namespace MyPass

[<RequireQualifiedAccess>]
[<CompilationRepresentation (CompilationRepresentationFlags.ModuleSuffix)>]
module Vault =

    let empty =
        {
            Passwords = Map.empty
            History = [||]
        }

    let private exceptionToFailure (f : unit -> Result<FailReason, 'b>) =
        try
            f ()
        with
        | ex ->
            FailReason.fromException ex
            |> Failure

    let storePassword
        (getTime : unit -> System.DateTime)
        (entry : PasswordEntry)
        (manager : Vault)
        : Result<FailReason, Vault>
        =
        let store = manager.Passwords
        let name = entry.Name
        if Map.containsKey name store then
            DuplicateEntry "Password entry already exists"
            |> Failure
        else
            let newStore = Map.add name entry store
            let activity = UserActivity.make (getTime ()) (Add name)
            {
                Passwords = newStore
                History = Array.append manager.History [| activity |]
            } |> Success

    /// Takes a new password entry and replaces another entry with the same key.
    /// Will fail if there is no entry with the provided name of the new entry.
    let updatePassword
        (getTime : unit -> System.DateTime)
        (entry : PasswordEntry)
        (manager : Vault)
        : Result<FailReason, Vault>
        =
        let store = manager.Passwords
        let name = entry.Name
        if Map.containsKey name store = false then
            EntryNotFound "Password entry not found"
            |> Failure
        else
            let newStore = Map.add name entry store
            let activity = UserActivity.make (getTime ()) (Update name)
            {
                Passwords = newStore
                History = Array.append manager.History [| activity |]
            } |> Success

    /// Removes a secret that has the provided name.
    /// Will fail if there is no secret with the provided name.
    let removePassword
        (getTime : unit -> System.DateTime)
        (name : Name)
        (manager : Vault)
        : Result<FailReason, Vault>
        =
        let store = manager.Passwords
        if Map.containsKey name store then
            let newStore = Map.remove name store
            let activity = UserActivity.make (getTime ()) (Delete name)
            {
                Passwords = newStore
                History = Array.append manager.History [| activity |]
            } |> Success
        else
            EntryNotFound "Password entry not found"
            |> Failure

    /// Encrypts a vault with the provided AES key.
    let encrypt
        (key : AesKey)
        (manager : Vault)
        : Result<FailReason, byte[]>
        =
        fun () ->
            manager
            |> VaultSerialisation.serialise
            |> String.toBytes
            |> fun data -> Aes.encrypt data key
            |> Success
        |> exceptionToFailure

    /// Decrypts a vault with the provided key.
    let decrypt
        (key : AesKey)
        (encryptedManager : byte[])
        : Result<FailReason, Vault>
        =
        fun () ->
            encryptedManager
            |> fun data -> Aes.decrypt data key
            |> String.fromBytes
            |> VaultSerialisation.deserialise
        |> exceptionToFailure

    /// Gets the password entry for the provided name.
    /// Will fail if no entry exists.
    let getPassword
        (getTime : unit -> System.DateTime)
        (name : Name)
        (manager : Vault)
        : Result<FailReason, PasswordEntry * Vault>
        =
        let store = manager.Passwords
        if Map.containsKey name store then
            let entry = Map.find name store
            let activity = UserActivity.make (getTime ()) (Get name)
            {
                Passwords = manager.Passwords
                History = Array.append manager.History [| activity |]
            } |> fun store -> Success (entry, store)
        else
            EntryNotFound "Unable to find a password matching that name."
            |> Failure

    /// Gets the part of the entry that aren't secret.
    let getPublicEntryDetails
        (getTime : unit -> System.DateTime)
        (name : Name)
        (manager : Vault)
        : Result<FailReason, PasswordEntry * Vault>
        =
        let store = manager.Passwords
        if Map.containsKey name store then
            let entry = Map.find name store
            let entryWithoutSecret =
                {
                    entry with
                        Secret =
                            match entry.Secret with
                            | Secret _ ->
                                SecuredSecret.createDummy ()
                                |> Secret
                            | WebLogin wl ->
                                {
                                    wl with
                                        SecuredData = SecuredSecret.createDummy ()
                                } |> WebLogin
                }
            let activity = UserActivity.make (getTime ()) (Details name)
            {
                Passwords = manager.Passwords
                History = Array.append manager.History [| activity |]
            } |> fun store -> Success (entryWithoutSecret, store)
        else
            EntryNotFound "Unable to find a password matching that name."
            |> Failure

    /// Clears the history from a vault, returning what has been removed
    let clearHistory
        (vault : Vault)
        : Result<FailReason, UserActivity array * Vault>
        =
        let history = vault.History
        (history, { vault with History = [||] })
        |> Success

    /// Finds all of the compromised entries in the vault.
    let getCompromisedPasswords
        (getTime : unit -> System.DateTime)
        (isCompromised : SecuredSecret -> Result<FailReason, CompromisedStatus>)
        (vault : Vault)
        : Result<FailReason, Name list * Vault>
        =

        let compromisedPasswords =
            vault.Passwords
            |> Map.toArray
            |> Array.map (Tuple.map PasswordEntry.getSecureData)
            |> Array.Parallel.map (Tuple.map isCompromised)
            |> Array.toList
            |> List.traverse (Tuple.sequence)
            |> Result.map (List.filter (fun (_,b) -> b = Compromised))
            |> Result.map (List.map fst)

        let newVault =
            let activity = UserActivity.make (getTime ()) BreachCheck
            { vault with History = Array.append vault.History [| activity |] }

        Result.map (fun comp -> comp, newVault) compromisedPasswords

    /// Returns sets of secrets that all share the same password
    let findReusedSecrets
        (getTime : unit -> System.DateTime)
        (vault : Vault)
        : Result<FailReason, Name list list * Vault>
        =

        let construct (data : (Name * Sha1Hash) list) : Map<Sha1Hash, Name list> =
            let rec construct (acc : Map<Sha1Hash, Name list>) ((n,h) : Name * Sha1Hash) =
                match Map.tryFind h acc with
                | Some data -> Map.add h (n::data) acc
                | None -> Map.add h [n] acc
            List.fold construct Map.empty data

        let dupePasswords =
            vault.Passwords
            |> Map.toList
            |> List.map (Tuple.map PasswordEntry.getSecureData)
            |> List.traverse (Tuple.traverse SecuredSecret.hash)
            |> Result.map construct
            |> Result.map (Map.toList >> List.map snd)
            |> Result.map (List.filter (fun l -> List.length l > 1))

        let newVault =
            let activity = UserActivity.make (getTime ()) DupeCheck
            { vault with History = Array.append vault.History [| activity |] }

        Result.map (fun comp -> comp, newVault) dupePasswords