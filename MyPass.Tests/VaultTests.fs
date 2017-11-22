namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result

module VaultTests =
    let testPasswordEntry = {
        Password = EncryptedPassword (Array.create 5 (byte 0))
        Key = Aes.newKey ()
        Description = BasicDescription ("www.gmail.com", "My gmail password")
    }
    let testPasswordEntry2 = {
        Password = EncryptedPassword (Array.create 5 (byte 0))
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