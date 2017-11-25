namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq

module PasswordTests =

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