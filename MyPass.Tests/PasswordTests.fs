namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq

module PasswordTests =

    [<Test>]
    [<Repeat(50)>]
    let ``When constructing password with extra chars, then no unspecified chars are used `` () =
        let extra = [|'@'; ';'; '\''; '\"'; '['|]
        let allValidChars = Array.concat [|Password.availableCharacters; extra|]
        let pw = Password.createWithExtraCharacters extra 15u
        pw.ToCharArray ()
        |> Array.map (fun c -> Array.contains c allValidChars)
        |> Array.fold (&&) true
        |> fun v -> Assert.IsTrue v

    [<Test>]
    [<Repeat(25)>]
    let ``When recreating the password with the same parameters then the password is the same`` () =
        let userId = Password.createPassword 15u
        let versionId = Password.createPassword 7u
        let masterPassPhrase = Password.createPassword 10u
        let secretKey = Array.create 10 (byte 0)
        let pwOne = Password.createMasterPassword versionId masterPassPhrase secretKey userId
        let pwTwo = Password.createMasterPassword versionId masterPassPhrase secretKey userId
        Assert.That(pwOne.SequenceEqual(pwTwo), Is.True)

    [<Test>]
    [<Repeat(5)>]
    let ``When recreating the password with the same parameters but different secretKey then the passwords differ`` () =
        let userId = Password.createPassword 15u
        let versionId = Password.createPassword 7u
        let masterPassPhrase = Password.createPassword 10u
        let secretKey = Array.create 10 (byte 0)
        let secretKey2 = Array.create 10 (byte 1)
        let pwOne = Password.createMasterPassword versionId masterPassPhrase secretKey userId
        let pwTwo = Password.createMasterPassword versionId masterPassPhrase secretKey2 userId
        Assert.That(pwOne.SequenceEqual(pwTwo), Is.False)

    [<Test>]
    [<Repeat(5)>]
    let ``When recreating the password with the same parameters but different userId then the passwords differ`` () =
        let userId = Password.createPassword 15u
        let userId2 = Password.createPassword 15u
        let versionId = Password.createPassword 7u
        let masterPassPhrase = Password.createPassword 10u
        let secretKey = Array.create 10 (byte 0)
        let pwOne = Password.createMasterPassword versionId masterPassPhrase secretKey userId
        let pwTwo = Password.createMasterPassword versionId masterPassPhrase secretKey userId2
        Assert.That(pwOne.SequenceEqual(pwTwo), Is.False)

    [<Test>]
    [<Repeat(5)>]
    let ``When recreating the password with the same parameters but different versionIds then the passwords differ`` () =
        let userId = Password.createPassword 15u
        let versionId = Password.createPassword 7u
        let versionId2 = Password.createPassword 7u
        let masterPassPhrase = Password.createPassword 10u
        let secretKey = Array.create 10 (byte 0)
        let pwOne = Password.createMasterPassword versionId masterPassPhrase secretKey userId
        let pwTwo = Password.createMasterPassword versionId2 masterPassPhrase secretKey userId
        Assert.That(pwOne.SequenceEqual(pwTwo), Is.False)

    [<Test>]
    [<Repeat(5)>]
    let ``When recreating the password with the same parameters but different passPhrases then the passwords differ`` () =
        let userId = Password.createPassword 15u
        let versionId = Password.createPassword 7u
        let masterPassPhrase = Password.createPassword 10u
        let masterPassPhrase2 = Password.createPassword 10u
        let secretKey = Array.create 10 (byte 0)
        let pwOne = Password.createMasterPassword versionId masterPassPhrase secretKey userId
        let pwTwo = Password.createMasterPassword versionId masterPassPhrase2 secretKey userId
        Assert.That(pwOne.SequenceEqual(pwTwo), Is.False)