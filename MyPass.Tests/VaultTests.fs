namespace MyPass.Tests

open NUnit.Framework
open MyPass
open MyPass.Result.Operators
open System.Linq

module VaultTests =

    let testPasswordEntry =
        {
            Tags = Set.empty
            Secret = SecuredSecret.create "gmailSecret" |> Secret
            Description = Description "My gmail password"
            Name = Name "www.gmail.com"
        }

    let testPasswordEntry2 =
        {
            Tags = Set.empty
            Secret = SecuredSecret.create "bingSecret" |> Secret
            Description = Description "My bing password"
            Name = Name "www.bing.com"
        }

    let testPasswordEntryDupe =
        {
            Tags = Set.empty
            Secret = SecuredSecret.create "bingSecret" |> Secret
            Description = Description "My bing password2"
            Name = Name "www.bing.com2"
        }

    let webLoginName = (Name "My google account")
    let testWebLogin =
        let secret =
            VaultDomain.makeWebLogin
            <!> (Url.make "https://www.google.com/")
            <*> (Result.lift (Name "testUsername"))
            <*> (Result.lift (SecuredSecret.create "test"))

        (PasswordEntry.create webLoginName (Description "TestDesc"))
        <!> secret

    let testPasswordEntry3 =
        let f = fun url ->
            {
                Tags = [Tag.fromString "password"] |> Set.ofList
                Secret = VaultDomain.makeWebLogin url (Name "jackma") (SecuredSecret.create "55")
                Description = Description "admin"
                Name = Name "admin"
            }
        Result.map f (Url.make "https://www.google.com")

    let private join (m1 : Map<'a, 'b>) (m2 : Map<'a, 'c>) : Map<'a, ('b * 'c) option> =
        let getKeys m = m |> Map.toList |> List.map fst
        let keys =
            List.concat [getKeys m1; getKeys m2]
            |> Set.ofList
        let getItem m1 m2 (k : 'a) : ('b * 'c) option =
            match (Map.tryFind k m1), (Map.tryFind k m2) with
            | Some b, Some c -> Some (b,c)
            | _ -> None
        Seq.fold (fun m k -> Map.add k (getItem m1 m2 k) m) Map.empty keys

    [<Test>]
    let ``When trying to delete non-existant password entry then failure is recorded`` () =
        let vault = Vault.empty
        let result = Vault.removePassword Time.get (Name "www.gmail.com") vault
        match result with
        | Success _ -> Assert.Fail()
        | Failure _ -> Assert.Pass ()

    [<Test>]
    let ``When trying to update non-existant password entry then failure is recorded`` () =
        let vault = Vault.empty
        let result = Vault.updatePassword Time.get testPasswordEntry vault
        match result with
        | Success _ -> Assert.Fail()
        | Failure _ -> Assert.Pass ()

    [<Test>]
    let ``When trying to add existing password entry then failure is recorded`` () =
        let vault = Vault.empty
        let result =
            Vault.storePassword Time.get testPasswordEntry vault
            >>= Vault.storePassword Time.get testPasswordEntry
        match result with
        | Success _ -> Assert.Fail()
        | Failure _ -> Assert.Pass ()

    [<Test>]
    let ``When to retrieve a non-existant password entry then a failure is returned`` () =
        let vault = Vault.empty
        let result = Vault.getPassword Time.get (Name "www.gmail.com") vault
        match result with
        | Success _ -> Assert.Fail()
        | Failure _ -> Assert.Pass ()

    [<Test>]
    let ``Given a password manager with a password, when I retrieve it then the result is the correct password`` () =
        let result =
            Vault.storePassword Time.get testPasswordEntry Vault.empty
            >>= Vault.storePassword Time.get testPasswordEntry2
            >>= Vault.getPassword Time.get (Name "www.gmail.com")
        match result with
        | Failure _ -> Assert.Fail()
        | Success pw -> Assert.That(fst pw, Is.EqualTo testPasswordEntry)

    [<Test>]
    let ``Given a vault, when I update the tags on an entry, then the new tag is stored`` () =
        let newTag = Tag.fromString "TestTag"
        let entry =
            Vault.storePassword Time.get testPasswordEntry Vault.empty
            >>= Vault.getPassword Time.get testPasswordEntry.Name
            >>= (fun (e,v) ->
                    let newE = PasswordEntry.addTag newTag e
                    newE >>= fun e -> Vault.updatePassword Time.get e v)
            >>= (Vault.getPublicEntryDetails Time.get testPasswordEntry.Name)
            |> Result.map fst

        match entry with
        | Failure f -> Assert.Fail (FailReason.toString f)
        | Success e ->
            Assert.That (Set.contains newTag e.Tags, Is.True)

    [<Test>]
    let ``Given a password manager with a password, encryption round-trip works`` () =
        let storePasswords =
            Vault.storePassword Time.get testPasswordEntry
            >=> Vault.storePassword Time.get testPasswordEntry2
            >=> (fun v -> Result.bind testPasswordEntry3 (fun pw -> Vault.storePassword Time.get pw v))
        let result = storePasswords Vault.empty
        match result with
        | Failure _ -> Assert.Fail ()
        | Success store ->
            let key = Aes.make ()
            let roundTripResult =
                Vault.encrypt key store
                >>= Vault.decrypt key

            match roundTripResult with
            | Failure f ->
                printfn "%s" <| FailReason.toString f
                Assert.Fail ()
            | Success decStore ->
                let success =
                    join decStore.Passwords store.Passwords
                    |> Map.toList
                    |> List.traverse
                        (fun ((Name n), k) ->
                            match k with
                            | None -> EntryNotFound n |> Failure
                            | Some (a,_) ->
                                (=) <!> (PasswordEntry.decrypt a) <*> (PasswordEntry.decrypt a))
                    |> Result.map (List.fold (&&) true)
                match success with
                | Failure _ -> Assert.Fail ("Some passwords were not the same")
                | Success b ->
                    match b with
                    | false -> Assert.Fail ("Some passwords were not the same")
                    | true -> Assert.Pass ()

    [<Test>]
    let ``Given a password manager with a password, encryption round-trip fails if different key is used to decrypt`` () =
        let storePasswords =
            Vault.storePassword Time.get testPasswordEntry
            >=> Vault.storePassword Time.get testPasswordEntry2
        let result = storePasswords Vault.empty      
        match result with
        | Failure _ -> Assert.Fail()
        | Success store ->
            let key = Aes.make ()
            let decKey = Aes.make ()
            let roundTrip = Vault.encrypt key >=> Vault.decrypt decKey
            let roundTripResult = roundTrip store
            match roundTripResult with
            | Failure _ -> Assert.Pass()
            | Success _ -> Assert.Fail()

    [<Test>]
    let ``Given a password manager with a password, when I remove it then it is removed.`` () =
        let result = Vault.storePassword Time.get testPasswordEntry Vault.empty
        match result with
        | Failure _ -> Assert.Fail()
        | Success pw ->
            Assert.That(pw.Passwords |> Map.toSeq |> Seq.length, Is.EqualTo 1)
            let updatedResult = Vault.removePassword Time.get (Name "www.gmail.com") pw
            match updatedResult with
            | Failure _ -> Assert.Fail()
            | Success pw -> Assert.That(pw.Passwords |> Map.toSeq |> Seq.length, Is.EqualTo 0)

    [<Test>]
    let ``Given a password manager when I create an entry then then password is retrieved.`` () =
        let password = "123pass"
        let entry =
            SecuredSecret.create password |> Secret
            |> PasswordEntry.create (Name "google") (Description "my google account")
        let result =
            Vault.storePassword Time.get entry Vault.empty
            >>= Vault.getPassword Time.get (Name "google")
            >>= (fun (en, va ) ->
                    PasswordEntry.decrypt en
                    |> Result.map (fun en -> en,va))
        match result with
        | Failure _ -> Assert.Fail()
        | Success p -> Assert.That(fst p, Is.EqualTo password)

    [<Test>]
    let ``Given a password manager when I create an entry then then password is retrieved and encrypted.`` () =
        let password = "123pass"
        let entry =
            SecuredSecret.create password |> Secret
            |> PasswordEntry.create (Name "google") (Description "my google account")
        let result =
            Vault.storePassword Time.get entry Vault.empty
            >>= Vault.getPassword Time.get (Name "google")
        match result with
        | Failure _ -> Assert.Fail()
        | Success p ->
            let (EncryptedData bytes) = (PasswordEntry.getSecureData >> SecuredSecret.getEncryptedData) (fst p)
            Assert.That(
                bytes.SequenceEqual(System.Text.Encoding.UTF8.GetBytes(password)),
                Is.False)

    [<Test>]
    let ``Given a password manager with a password, when I update it then it is updated.`` () =
        let updatedEntry =
            PasswordEntry.updateSecret
                (SecuredSecret.create "newPassword")
                testPasswordEntry
        let result =
            Vault.storePassword Time.get testPasswordEntry Vault.empty
            |> fun vault -> Result.bind2 updatedEntry vault (Vault.updatePassword Time.get)
            >>= Vault.getPassword Time.get (Name "www.gmail.com")
        match result with
        | Failure _ -> Assert.Fail ()
        | Success pw ->
            let pwOne = updatedEntry >>= PasswordEntry.decrypt
            let pwTwo = PasswordEntry.decrypt (fst pw)
            match pwOne,pwTwo with
            | Success a, Success b ->
                Assert.That (a, Is.EqualTo(b))
            | _ -> Assert.Fail ()

    [<Test>]
    let ``Given a password manager, when I search for dupe passwords, then correct results are returned`` () =
        let vault =
            Vault.storePassword Time.get testPasswordEntry Vault.empty
            >>= Vault.storePassword Time.get testPasswordEntry2
            >>= Vault.storePassword Time.get testPasswordEntryDupe
        let results = vault >>= (Vault.findReusedSecrets Time.get)
        match results with
        | Success ((a::[]), _) ->
            Assert.That(a, Is.EqualTo([Name "www.bing.com2"; Name "www.bing.com"]))
        | _ -> Assert.Fail "Expected to see a single list returned."

    [<Test>]
    let ``Given a password manager and some operations, when we check the history, then the history is accurate`` () =
        let now = System.DateTime.UtcNow
        let dates =
            [| 1.0 .. 10.0 |]
            |> Array.map (fun i -> now.AddDays(i))

        let getTime =
            let mutable counter = 0
            fun () ->
                let date = dates.[counter]
                counter <- counter + 1
                date

        let expected =
            [|
                sprintf "%s - %s" (dates.[0].ToString("G")) ("Added www.gmail.com to the vault.")
                sprintf "%s - %s" (dates.[1].ToString("G")) ("Added www.bing.com to the vault.")
                sprintf "%s - %s" (dates.[2].ToString("G")) ("Deleted www.bing.com from the vault.")
                sprintf "%s - %s" (dates.[3].ToString("G")) ("Updated www.gmail.com in the vault.")
                sprintf "%s - %s" (dates.[4].ToString("G")) ("Performed a secret reuse check.")
                sprintf "%s - %s" (dates.[5].ToString("G")) ("Performed a breach check with HaveIBeenPwned.")
                sprintf "%s - %s" (dates.[6].ToString("G")) ("Got the secret of www.gmail.com.")
                sprintf "%s - %s" (dates.[7].ToString("G")) ("Got the public details of www.gmail.com.")
            |]

        let updatedEntry =
            PasswordEntry.updateSecret
                (SecuredSecret.create "newPassword")
                testPasswordEntry
        let vault =
            Vault.storePassword getTime testPasswordEntry Vault.empty
            >>= Vault.storePassword getTime testPasswordEntry2
            >>= Vault.removePassword  getTime (testPasswordEntry2.Name)
            >>= Vault.updatePassword getTime updatedEntry
            >>= Vault.findReusedSecrets getTime
            |> Result.map snd
            >>= Vault.getCompromisedPasswords getTime (fun _ -> Success NotCompromised)
            |> Result.map snd
            >>= Vault.getPassword  getTime (testPasswordEntry.Name)
            |> Result.map snd
            >>= Vault.getPublicEntryDetails  getTime (testPasswordEntry.Name)
            |> Result.map snd

        match vault with
        | Failure _ -> Assert.Fail ()
        | Success v ->
            let historyData =
                v.History
                |> Array.map UserActivity.toString
            Assert.That(historyData, Is.EqualTo expected)

    [<Test>]
    let ``Given a password manager and some operations, when history is cleared, then correct history is returned`` () =
        let now = System.DateTime.UtcNow
        let dates =
            [| 1.0 .. 10.0 |]
            |> Array.map (fun i -> now.AddDays(i))

        let getTime =
            let mutable counter = 0
            fun () ->
                let date = dates.[counter]
                counter <- counter + 1
                date

        let expected =
            [|
                sprintf "%s - %s" (dates.[0].ToString("G")) ("Added www.gmail.com to the vault.")
                sprintf "%s - %s" (dates.[1].ToString("G")) ("Added www.bing.com to the vault.")
                sprintf "%s - %s" (dates.[2].ToString("G")) ("Deleted www.bing.com from the vault.")
                sprintf "%s - %s" (dates.[3].ToString("G")) ("Updated www.gmail.com in the vault.")
                sprintf "%s - %s" (dates.[4].ToString("G")) ("Performed a secret reuse check.")
                sprintf "%s - %s" (dates.[5].ToString("G")) ("Performed a breach check with HaveIBeenPwned.")
                sprintf "%s - %s" (dates.[6].ToString("G")) ("Got the secret of www.gmail.com.")
                sprintf "%s - %s" (dates.[7].ToString("G")) ("Got the public details of www.gmail.com.")
            |]

        let updatedEntry =
            PasswordEntry.updateSecret
                (SecuredSecret.create "newPassword")
                testPasswordEntry
        let vault =
            Vault.storePassword getTime testPasswordEntry Vault.empty
            >>= Vault.storePassword getTime testPasswordEntry2
            >>= Vault.removePassword  getTime (testPasswordEntry2.Name)
            >>= Vault.updatePassword getTime updatedEntry
            >>= Vault.findReusedSecrets getTime
            |> Result.map snd
            >>= Vault.getCompromisedPasswords getTime (fun _ -> Success NotCompromised)
            |> Result.map snd
            >>= Vault.getPassword  getTime (testPasswordEntry.Name)
            |> Result.map snd
            >>= Vault.getPublicEntryDetails  getTime (testPasswordEntry.Name)
            |> Result.map snd
            |> Result.map Vault.clearHistory

        match vault with
        | Failure _ -> Assert.Fail ()
        | Success (history, v) ->
            Assert.That(history |> Array.map UserActivity.toString, Is.EqualTo expected)
            Assert.That (v.History, Is.Empty)

    [<Test>]
    let ``Given a Vault with a secret, when I request the public details, then I can't access the password`` () =

        let vault = Vault.storePassword Time.get testPasswordEntry Vault.empty
        let publicEntryWithVault =
            Result.bind vault (Vault.getPublicEntryDetails Time.get testPasswordEntry.Name)
        let publicEntry = Result.map fst publicEntryWithVault
        let updatedVault = Result.map snd publicEntryWithVault
        let actualPassword =
            Result.bind updatedVault (Vault.getPassword Time.get testPasswordEntry.Name)
            |> Result.map fst

        match actualPassword with
        | Success p ->
            Assert.That(p, Is.EqualTo testPasswordEntry)
        | Failure _ -> Assert.Fail ()

        match publicEntry with
        | Failure _ -> Assert.Fail ()
        | Success p ->
            match p.Secret with
            | Secret s ->
                match SecuredSecret.getEncryptedData s with
                | (EncryptedData d) -> Assert.That(d.Length, Is.Zero)
            | WebLogin _ -> Assert.Fail ()

    [<Test>]
    let ``Given a Vault with a web login, when I request the public details, then I can't access the password`` () =

        let vault = Result.bind testWebLogin (fun e -> Vault.storePassword Time.get e Vault.empty)
        let publicEntryWithVault =
            Result.bind vault (Vault.getPublicEntryDetails Time.get webLoginName)

        let updatedVault = Result.map snd publicEntryWithVault
        let publicEntry = Result.map fst publicEntryWithVault

        let actualPassword =
            Result.bind updatedVault (Vault.getPassword Time.get webLoginName)
            |> Result.map fst

        match actualPassword with
        | Success p ->
            match p.Secret with
            | WebLogin wl ->
                let pw = SecuredSecret.decrypt wl.SecuredData
                match pw with
                | Failure _ -> Assert.Fail ()
                | Success pw ->
                    Assert.That(pw, Is.EqualTo ("test"))
            | _ -> Assert.Fail ()
        | Failure _ -> Assert.Fail ()

        match publicEntry with
        | Failure _ -> Assert.Fail ()
        | Success p ->
            match p.Secret with
            | WebLogin wl ->
                match SecuredSecret.getEncryptedData wl.SecuredData with
                | (EncryptedData d) -> Assert.That(d.Length, Is.Zero)
            | _ -> Assert.Fail ()

    [<Test>]
    let ``Given an old Vault dto, when converted to a vault then the vault functions`` () =
        let vdto = "{\"PasswordList\" : []}"
        let vault = VaultSerialisation.deserialise vdto
        match vault with
        | Failure _ -> Assert.Fail ()
        | Success v ->
            let historyData = v.History.Length
            Assert.That(historyData, Is.EqualTo 0)