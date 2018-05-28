namespace MyPass.Tests

open NUnit.Framework
open System.Linq
open MyPass

module AesTests =

    [<Test>]
    [<Repeat(10000)>]
    let ``Aes Roundtrip``() =
        let aes = Aes.make ()
        let dataToEncrypt = "HelloWorld" |> System.Text.Encoding.UTF8.GetBytes
        let encrypted = Aes.encrypt aes dataToEncrypt
        let decrypted = Aes.decrypt aes encrypted
        Assert.That(dataToEncrypt.SequenceEqual(encrypted), Is.False)
        Assert.That(dataToEncrypt.SequenceEqual(decrypted), Is.True)

    [<Test>]
    let ``Given a passphrase and a salt, when an Aes key is generated then it is identical on multiple calls`` () =
        let salt = Salt "salty"
        let passphrase = PassPhrase "This is a test"
        let keyOne = Aes.generateFromPassPhrase salt passphrase
        let keyTwo = Aes.generateFromPassPhrase salt passphrase
        Assert.That(keyOne.Key.SequenceEqual(keyTwo.Key), Is.True)

    [<Test>]
    let ``Given a passphrase and a two salts, when an Aes key is generated then it is different based on salt`` () =
        let salt = Salt "salty"
        let salt2 = Salt "salty2"
        let passphrase = PassPhrase "This is a test"
        let keyOne = Aes.generateFromPassPhrase salt passphrase
        let keyTwo = Aes.generateFromPassPhrase salt2 passphrase
        Assert.That(keyOne.Key.SequenceEqual(keyTwo.Key), Is.False)

    [<Test>]
    let ``Given a two passphrase and a salt, when an Aes key is generated then it is different based on passphrase`` () =
        let salt = Salt "salty"
        let passphrase = PassPhrase "salty2"
        let passphrase2 = PassPhrase "This is a test"
        let keyOne = Aes.generateFromPassPhrase salt passphrase
        let keyTwo = Aes.generateFromPassPhrase salt passphrase2
        Assert.That(keyOne.Key.SequenceEqual(keyTwo.Key), Is.False)