namespace MyPass.Tests

open NUnit.Framework
open MyPass
open MyPass.SecureString

module PasswordTests =

    let rec private generateDifferentPassword (pw : string) (genPass : unit -> string) : string =
        let len = pw.Length
        let newPass = genPass ()
        match newPass = pw with
        | true -> generateDifferentPassword pw genPass
        | false -> newPass

    [<Test>]
    [<Repeat(50)>]
    let ``When constructing password with extra chars, then no unspecified chars are used `` () =
        let extra = [|'@'; ';'; '\''; '\"'; '['|]
        let allValidChars = Array.concat [|Password.alphanumericCharacters; extra|]
        let pw =
            Password.createWithExtraCharacters extra 15u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        pw.ToCharArray ()
        |> Array.map (fun c -> Array.contains c allValidChars)
        |> Array.fold (&&) true
        |> fun v -> Assert.IsTrue v

    [<Test>]
    [<Repeat(25)>]
    let ``When recreating the password with the same parameters then the password is the same`` () =
        let userId =
            Password.createPassword 15u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let versionId =
            Password.createPassword 7u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let masterPassPhrase = Password.createPassword 10u
        let secretKey = Array.create 10 (byte 0)
        let pwOne = MasterKey.make versionId secretKey userId masterPassPhrase
        let pwTwo = MasterKey.make versionId secretKey userId masterPassPhrase
        Assert.That(AesTests.roundTripWorks pwOne pwTwo, Is.True)

    [<Test>]
    [<Repeat(5)>]
    let ``When recreating the password with the same parameters but different secretKey then the passwords differ`` () =
        let userId =
            Password.createPassword 15u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let versionId =
            Password.createPassword 7u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let masterPassPhrase = Password.createPassword 10u
        let secretKey = Array.create 10 (byte 0)
        let secretKey2 = Array.create 10 (byte 1)
        let pwOne = MasterKey.make versionId secretKey userId masterPassPhrase
        let pwTwo = MasterKey.make versionId secretKey2 userId masterPassPhrase
        Assert.That(AesTests.roundTripWorks pwOne pwTwo, Is.False)

    [<Test>]
    [<Repeat(5)>]
    let ``When recreating the password with the same parameters but different userId then the passwords differ`` () =
        let userId =
            Password.createPassword 15u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let versionId =
            Password.createPassword 7u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let masterPassPhrase = Password.createPassword 10u
        let userId2 =
            generateDifferentPassword
                userId
                (fun () -> Password.createPassword 15u |> fun p -> SecurePasswordHandler.Use(p, fun p -> String.fromBytes p))
        let secretKey = Array.create 10 (byte 0)
        let pwOne = MasterKey.make versionId secretKey userId masterPassPhrase
        let pwTwo = MasterKey.make versionId secretKey userId2 masterPassPhrase
        Assert.That(AesTests.roundTripWorks pwOne pwTwo, Is.False)

    [<Test>]
    [<Repeat(5)>]
    let ``When recreating the password with the same parameters but different versionIds then the passwords differ`` () =
        let userId =
            Password.createPassword 15u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let versionId =
            Password.createPassword 7u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let masterPassPhrase = Password.createPassword 10u
        let versionId2 =
            generateDifferentPassword
                versionId
                (fun () -> Password.createPassword 15u |> fun p -> SecurePasswordHandler.Use(p, fun p -> String.fromBytes p))
        let secretKey = Array.create 10 (byte 0)
        let pwOne = MasterKey.make versionId secretKey userId masterPassPhrase
        let pwTwo = MasterKey.make versionId2 secretKey userId masterPassPhrase
        Assert.That(AesTests.roundTripWorks pwOne pwTwo, Is.False)

    [<Test>]
    [<Repeat(5)>]
    let ``When recreating the password with the same parameters but different passPhrases then the passwords differ`` () =
        let userId =
            Password.createPassword 15u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let versionId =
            Password.createPassword 7u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> p |> String.fromBytes)
        let masterPassPhrase = Password.createPassword 10u
        let masterPassPhrase2 =
            generateDifferentPassword
                (SecurePasswordHandler.Use(masterPassPhrase, fun p -> String.fromBytes p))
                (fun () -> Password.createPassword 10u |> fun p -> SecurePasswordHandler.Use(p, fun p -> String.fromBytes p))
            |> SecureString.fromString
        let secretKey = Array.create 10 (byte 0)
        let pwOne = MasterKey.make versionId secretKey userId masterPassPhrase
        let pwTwo = MasterKey.make versionId secretKey userId masterPassPhrase2
        Assert.That(AesTests.roundTripWorks pwOne pwTwo, Is.False)