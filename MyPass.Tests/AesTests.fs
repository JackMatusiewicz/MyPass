namespace MyPass.Tests

open NUnit.Framework
open System.Security.Cryptography
open System.Linq
open MyPass

module AesTests =

    [<Test>]
    [<Repeat(10000)>]
    let ``Aes Roundtrip``() =
        let aes = Aes.newKey ()
        let dataToEncrypt = "HelloWorld" |> System.Text.Encoding.UTF8.GetBytes
        let encrypted = Aes.encrypt aes dataToEncrypt
        let decrypted = Aes.decrypt aes encrypted
        Assert.That(dataToEncrypt.SequenceEqual(encrypted), Is.False)
        Assert.That(dataToEncrypt.SequenceEqual(decrypted), Is.True)