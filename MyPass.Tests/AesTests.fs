namespace MyPass.Tests

open NUnit.Framework
open System.Linq
open MyPass

module AesTests =

    let roundTripWorks (k1 : AesKey) (k2 : AesKey) =
        try
            "testStringHere"
            |> System.Text.Encoding.UTF8.GetBytes
            |> fun bs -> Aes.encrypt bs k1
            |> fun bs -> Aes.decrypt bs k2
            |> System.Text.Encoding.UTF8.GetString
            |> fun w -> w = "testStringHere"
        with
        | _ -> false

    [<Test>]
    [<Repeat(10000)>]
    let ``Aes Roundtrip``() =
        let aes = Aes.make ()
        let dataToEncrypt = "HelloWorld" |> System.Text.Encoding.UTF8.GetBytes
        let encrypted = Aes.encrypt dataToEncrypt aes
        let decrypted = Aes.decrypt encrypted aes
        Assert.That(dataToEncrypt.SequenceEqual(encrypted), Is.False)
        Assert.That(dataToEncrypt.SequenceEqual(decrypted), Is.True)

    [<Test>]
    [<Repeat(10000)>]
    let ``Aes roundtrip fails with different keys`` () =
        let k1 = Aes.make ()
        let k2 = Aes.make ()
        Assert.That (roundTripWorks k1 k2, Is.False)

    [<Test>]
    let ``Given a passphrase and a salt, when an Aes key is generated then it is identical on multiple calls`` () =
        let salt = Salt "salty"
        let passphrase = PassPhrase "This is a test"
        let keyOne = Aes.generateFromPassPhrase salt passphrase
        let keyTwo = Aes.generateFromPassPhrase salt passphrase

        Assert.That(roundTripWorks keyOne keyTwo, Is.True)

    [<Test>]
    let ``Given a passphrase and a two salts, when an Aes key is generated then it is different based on salt`` () =
        let salt = Salt "salty"
        let salt2 = Salt "salty2"
        let passphrase = PassPhrase "This is a test"
        let keyOne = Aes.generateFromPassPhrase salt passphrase
        let keyTwo = Aes.generateFromPassPhrase salt2 passphrase
        Assert.That(roundTripWorks keyOne keyTwo, Is.False)

    [<Test>]
    let ``Given a two passphrase and a salt, when an Aes key is generated then it is different based on passphrase`` () =
        let salt = Salt "salty"
        let passphrase = PassPhrase "salty2"
        let passphrase2 = PassPhrase "This is a test"
        let keyOne = Aes.generateFromPassPhrase salt passphrase
        let keyTwo = Aes.generateFromPassPhrase salt passphrase2
        Assert.That(roundTripWorks keyOne keyTwo, Is.False)