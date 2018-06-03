namespace MyPass.Tests

open NUnit.Framework
open MyPass
open MyPass.Result.Operators
open Result
open System.Linq

module VaultTests =

    let testPasswordEntry = {
        Secret = SecuredSecret.create "gmailSecret" |> Secret
        Description = Description "My gmail password"
        Name = Name "www.gmail.com"
    }

    let testPasswordEntry2 = {
        Secret = SecuredSecret.create "bingSecret" |> Secret
        Description = Description "My bing password"
        Name = Name "www.bing.com"
    }

    let testPasswordEntry3 =
        let f = fun url ->
            {
                Secret = VaultDomain.makeWebLogin url (Name "jackma") (SecuredSecret.create "55")
                Description = Description "admin"
                Name = Name "admin"
            }
        Result.map f (Url.make "https://www.google.com")

    [<Test>]
    let ``When trying to delete non-existant password entry then failure is recorded`` () =
        let vault = Vault.empty
        let result = Vault.removePassword (Name "www.gmail.com") vault
        match result with
        | Success _ -> Assert.Fail()
        | Failure s -> Assert.Pass ()

    [<Test>]
    let ``When trying to update non-existant password entry then failure is recorded`` () =
        let vault = Vault.empty
        let result = Vault.updatePassword testPasswordEntry vault
        match result with
        | Success _ -> Assert.Fail()
        | Failure s -> Assert.Pass ()

    [<Test>]
    let ``When trying to add existing password entry then failure is recorded`` () =
        let vault = Vault.empty
        let result =
            Vault.storePassword testPasswordEntry vault
            >>= Vault.storePassword testPasswordEntry
        match result with
        | Success _ -> Assert.Fail()
        | Failure s -> Assert.Pass ()

    [<Test>]
    let ``When to retrieve a non-existant password entry then a failure is returned`` () =
        let vault = Vault.empty
        let result = Vault.getPassword (Name "www.gmail.com") vault
        match result with
        | Success _ -> Assert.Fail()
        | Failure s -> Assert.Pass ()

    [<Test>]
    let ``Given a password manager with a password, when I retrieve it then the result is the correct password`` () =
        let result =
            Vault.storePassword testPasswordEntry Vault.empty
            >>= Vault.storePassword testPasswordEntry2
            >>= Vault.getPassword (Name "www.gmail.com")
        match result with
        | Failure _ -> Assert.Fail()
        | Success pw -> Assert.That(pw, Is.EqualTo testPasswordEntry)

    [<Test>]
    let ``Given a password manager with a password, encryption round-trip works`` () =
        let storePasswords =
            Vault.storePassword testPasswordEntry
            >=> Vault.storePassword testPasswordEntry2
            >=> (fun v -> Result.bind testPasswordEntry3 (fun pw -> Vault.storePassword pw v))
        let result = storePasswords Vault.empty
        match result with
        | Failure _ -> Assert.Fail()
        | Success store ->
            let key = Aes.make ()
            let roundTripResult =
                Vault.encrypt key store
                >>= Vault.decrypt key
            match roundTripResult with
            | Failure f ->
                printfn "%s" <| FailReason.toString f
                Assert.Fail()
            | Success decStore -> Assert.That(decStore, Is.EqualTo(store))

    [<Test>]
    let ``Given a password manager with a password, encryption round-trip fails if different key is used to decrypt`` () =
        let storePasswords =
            Vault.storePassword testPasswordEntry
            >=> Vault.storePassword testPasswordEntry2
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
            | Success decStore -> Assert.Fail()

    [<Test>]
    let ``Given a password manager with a password, when I remove it then it is removed.`` () =
        let result = Vault.storePassword testPasswordEntry Vault.empty
        match result with
        | Failure _ -> Assert.Fail()
        | Success pw ->
            Assert.That(pw.passwords |> Map.toSeq |> Seq.length, Is.EqualTo 1)
            let updatedResult = Vault.removePassword (Name "www.gmail.com") pw
            match updatedResult with
            | Failure _ -> Assert.Fail()
            | Success pw -> Assert.That(pw.passwords |> Map.toSeq |> Seq.length, Is.EqualTo 0)

    [<Test>]
    let ``Given a password manager when I create an entry then then password is retrieved.`` () =
        let password = "123pass"
        let entry =
            SecuredSecret.create password |> Secret
            |> PasswordEntry.create (Name "google") (Description "my google account")
        let result =
            Vault.storePassword entry Vault.empty
            >>= Vault.getPassword (Name "google")
            >>= PasswordEntry.decrypt
        match result with
        | Failure _ -> Assert.Fail()
        | Success p -> Assert.That(p, Is.EqualTo password)

    [<Test>]
    let ``Given a password manager when I create an entry then then password is retrieved and encrypted.`` () =
        let password = "123pass"
        let entry =
            SecuredSecret.create password |> Secret
            |> PasswordEntry.create (Name "google") (Description "my google account")
        let result =
            Vault.storePassword entry Vault.empty
            >>= Vault.getPassword (Name "google")
        match result with
        | Failure _ -> Assert.Fail()
        | Success p ->
            let (EncryptedData bytes) = (PasswordEntry.getSecureData >> SecuredSecret.getEncryptedData) p
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
            Vault.storePassword testPasswordEntry Vault.empty
            >>= Vault.updatePassword updatedEntry
            >>= Vault.getPassword (Name "www.gmail.com")
        match result with
        | Failure _ -> Assert.Fail ()
        | Success pw ->
            let pwOne = PasswordEntry.decrypt updatedEntry
            let pwTwo = PasswordEntry.decrypt pw
            match pwOne,pwTwo with
            | Success a, Success b ->
                Assert.That (a, Is.EqualTo(b))
            | _ -> Assert.Fail ()