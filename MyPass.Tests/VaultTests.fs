namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq

module VaultTests =
    let testPasswordEntry = {
        Password = EncryptedPassword (Array.create 5 (byte 0))
        Key = Aes.newKey ()
        Description = BasicDescription ("www.gmail.com", "My gmail password")
    }
    let testPasswordEntry2 = {
        Password = EncryptedPassword (Array.create 5 (byte 1))
        Key = Aes.newKey ()
        Description = BasicDescription ("www.bing.com", "My bing password")
    }

    [<Test>]
    let ``When trying to delete non-existant password entry then failure is recorded`` () =
        let vault = Vault.empty
        let result = Vault.removePassword "www.gmail.com" vault
        match result with
        | Success _ -> Assert.Fail()
        | Failure s -> Assert.That(s, Is.EqualTo("Password entry did not exist under that name."))

    [<Test>]
    let ``When trying to update non-existant password entry then failure is recorded`` () =
        let vault = Vault.empty
        let result = Vault.updatePassword testPasswordEntry vault
        match result with
        | Success _ -> Assert.Fail()
        | Failure s -> Assert.That(s, Is.EqualTo("Password entry does not exist"))

    [<Test>]
    let ``When trying to add existing password entry then failure is recorded`` () =
        let vault = Vault.empty
        let result = Vault.storePassword testPasswordEntry vault >>= Vault.storePassword testPasswordEntry
        match result with
        | Success _ -> Assert.Fail()
        | Failure s -> Assert.That(s, Is.EqualTo("Password entry already exists"))

    [<Test>]
    let ``When to retrieve a non-existant password entry then a failure is returned`` () =
        let vault = Vault.empty
        let result = Vault.getPassword "www.gmail.com" vault
        match result with
        | Success _ -> Assert.Fail()
        | Failure s -> Assert.That(s, Is.EqualTo("Unable to find a password matching that name."))

    [<Test>]
    let ``Given a password manager with a password, when I retrieve it then the result is the correct password`` () =
        let result = Vault.storePassword testPasswordEntry Vault.empty
                        >>= Vault.storePassword testPasswordEntry2
                        >>= Vault.getPassword "www.gmail.com"
        match result with
        | Failure _ -> Assert.Fail()
        | Success pw -> Assert.That(pw, Is.EqualTo testPasswordEntry)

    [<Test>]
    let ``Given a password manager with a password, encryption round-trip works`` () =
        let result = Vault.storePassword testPasswordEntry Vault.empty
                        >>= Vault.storePassword testPasswordEntry2
        match result with
        | Failure _ -> Assert.Fail()
        | Success store ->
            let key = Aes.newKey ()
            let roundTripResult = Vault.encryptManager key store
                                    >>= Vault.decryptManager key
            match roundTripResult with
            | Failure _ -> Assert.Fail()
            | Success decStore -> Assert.That(decStore, Is.EqualTo(store))

    [<Test>]
    let ``Given a password manager with a password, encryption round-trip fails if different key is used to decrypt`` () =
        let result = Vault.storePassword testPasswordEntry Vault.empty
                        >>= Vault.storePassword testPasswordEntry2
        match result with
        | Failure _ -> Assert.Fail()
        | Success store ->
            let key = Aes.newKey ()
            let decKey = Aes.newKey ()
            let roundTripResult = Vault.encryptManager key store
                                    >>= Vault.decryptManager decKey
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
            let updatedResult = Vault.removePassword "www.gmail.com" pw
            match updatedResult with
            | Failure _ -> Assert.Fail()
            | Success pw -> Assert.That(pw.passwords |> Map.toSeq |> Seq.length, Is.EqualTo 0)

    [<Test>]
    let ``Given a password manager when I create an entry then then password is retrieved.`` () =
        let desc = BasicDescription ("google", "my google account")
        let password = "123pass"
        let entry = Vault.createEntry desc password
        let result = Vault.storePassword entry Vault.empty
                        >>= Vault.getPassword "google"
                        >>= Vault.decryptPassword
        match result with
        | Failure _ -> Assert.Fail()
        | Success p -> Assert.That(p, Is.EqualTo password)

    [<Test>]
    let ``Given a password manager when I create an entry then then password is retrieved and encrypted.`` () =
        let desc = BasicDescription ("google", "my google account")
        let password = "123pass"
        let entry = Vault.createEntry desc password
        let result = Vault.storePassword entry Vault.empty
                        >>= Vault.getPassword "google"
        match result with
        | Failure _ -> Assert.Fail()
        | Success p -> Assert.That(p.Password, Is.Not.EqualTo <| System.Text.Encoding.UTF8.GetBytes(password))

    [<Test>]
    let ``Given a password manager with a password, when I update it then it is updated.`` () =
        let pwBytes = (Array.create 5 (byte 1))
        let updatedEntry = {testPasswordEntry with Password = EncryptedPassword pwBytes}
        let result = Vault.storePassword testPasswordEntry Vault.empty
                        >>= Vault.updatePassword updatedEntry
                        >>= Vault.getPassword "www.gmail.com"
        match result with
        | Failure _ -> Assert.Fail()
        | Success pw -> 
            let (EncryptedPassword encryptedPw) = pw.Password
            Assert.That(encryptedPw.SequenceEqual(pwBytes), Is.True)

    [<Test>]
    let ``Given a password entry that is a full description, when I get the name from it then the correct name is returned`` () =
        let fullDesc = FullDescription ("google", "www.google.com", "My google account")
        let password = "123pass"
        let entry = Vault.createEntry fullDesc password
        let result = Vault.storePassword entry Vault.empty
                        >>= Vault.getPassword "google"
                        >>= Vault.decryptPassword
        match result with
        | Failure _ -> Assert.Fail()
        | Success p -> Assert.That(p, Is.EqualTo password)