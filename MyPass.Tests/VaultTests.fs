namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq

module VaultTests =

    let testPasswordEntry = {
        Secret =
            {
                Data = EncryptedData (Array.create 5 (byte 0))
                Key = Aes.newKey ()
            } |> Secret
        Description = Description "My gmail password"
        Name = Name "www.gmail.com"
    }

    let testPasswordEntry2 = {
        Secret =
            {
                Data = EncryptedData (Array.create 5 (byte 1))
                Key = Aes.newKey ()
            } |> Secret
        Description = Description "My bing password"
        Name = Name "www.bing.com"
    }

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
        let result = Vault.storePassword testPasswordEntry vault >>= Vault.storePassword testPasswordEntry
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
        let storePasswords = Vault.storePassword testPasswordEntry >=> Vault.storePassword testPasswordEntry2
        let result = storePasswords Vault.empty
        match result with
        | Failure _ -> Assert.Fail()
        | Success store ->
            let key = Aes.newKey ()
            let roundTripResult =
                Vault.encryptManager key store
                >>= Vault.decryptManager key
            match roundTripResult with
            | Failure _ -> Assert.Fail()
            | Success decStore -> Assert.That(decStore, Is.EqualTo(store))

    [<Test>]
    let ``Given a password manager with a password, encryption round-trip fails if different key is used to decrypt`` () =
        let storePasswords = Vault.storePassword testPasswordEntry >=> Vault.storePassword testPasswordEntry2
        let result = storePasswords Vault.empty      
        match result with
        | Failure _ -> Assert.Fail()
        | Success store ->
            let key = Aes.newKey ()
            let decKey = Aes.newKey ()
            let roundTrip = Vault.encryptManager key >=> Vault.decryptManager decKey
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
            Vault.createSecret password
            |> Vault.createEntry (Name "google") (Description "my google account")
        let result =
            Vault.storePassword entry Vault.empty
            >>= Vault.getPassword (Name "google")
            >>= Vault.decryptPassword
        match result with
        | Failure _ -> Assert.Fail()
        | Success p -> Assert.That(p, Is.EqualTo password)

    [<Test>]
    let ``Given a password manager when I create an entry then then password is retrieved and encrypted.`` () =
        let password = "123pass"
        let entry =
            Vault.createSecret password
            |> Vault.createEntry (Name "google") (Description "my google account")
        let result =
            Vault.storePassword entry Vault.empty
            >>= Vault.getPassword (Name "google")
        match result with
        | Failure _ -> Assert.Fail()
        | Success p ->
            Assert.That(
                (Vault.getSecureData p).Data,
                Is.Not.EqualTo <| System.Text.Encoding.UTF8.GetBytes(password))

    [<Test>]
    let ``Given a password manager with a password, when I update it then it is updated.`` () =
        let pwBytes = (Array.create 5 (byte 1))
        let updatedEntry =
            {testPasswordEntry with
                Secret = {Data = EncryptedData pwBytes; Key = Aes.newKey ()} |> Secret}
        let result =
            Vault.storePassword testPasswordEntry Vault.empty
            >>= Vault.updatePassword updatedEntry
            >>= Vault.getPassword (Name "www.gmail.com")
        match result with
        | Failure _ -> Assert.Fail()
        | Success pw -> 
            let (EncryptedData encryptedPw) = (Vault.getSecureData pw).Data
            Assert.That(encryptedPw.SequenceEqual(pwBytes), Is.True)