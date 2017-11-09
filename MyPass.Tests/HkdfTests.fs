namespace MyPass.Tests

open NUnit.Framework
open System.Security.Cryptography
open System.Linq
open MyPass

module HkdfTests =

    [<Test>]
    [<Repeat(1000)>]
    let ``Using the same parameters yields the same expanded data``() =
        let initialKey = "fakeKeyData" |> System.Text.Encoding.UTF8.GetBytes
        let salt = "my.test.email@provider.com" |> System.Text.Encoding.UTF8.GetBytes
        let info = Array.create 0 (byte 0)
        let keyOne = Hkdf.expand initialKey salt info 32
        let keyTwo = Hkdf.expand initialKey salt info 32
        Assert.That(keyOne.Length, Is.EqualTo(32))
        Assert.That(keyOne.SequenceEqual(keyTwo), Is.True)

    [<Test>]
    [<Repeat(1000)>]
    let ``Different info values results in different expanded keys``() =
        let initialKey = "fakeKeyData" |> System.Text.Encoding.UTF8.GetBytes
        let salt = "my.test.email@provider.com" |> System.Text.Encoding.UTF8.GetBytes
        let info = Array.create 1 (byte 0)
        let info2 = Array.create 1 (byte 5)
        let keyOne = Hkdf.expand initialKey salt info 32
        let keyTwo = Hkdf.expand initialKey salt info2 32
        Assert.That(keyOne.Length, Is.EqualTo(32))
        Assert.That(keyTwo.Length, Is.EqualTo(32))
        Assert.That(keyOne.SequenceEqual(keyTwo), Is.False)

    [<Test>]
    [<Repeat(1000)>]
    let ``Different salt values results in different expanded keys``() =
        let initialKey = "fakeKeyData" |> System.Text.Encoding.UTF8.GetBytes
        let salt = "my.test.email@provider.com" |> System.Text.Encoding.UTF8.GetBytes
        let saltTwo = "my.main.email@badProvider.com" |> System.Text.Encoding.UTF8.GetBytes
        let info = Array.create 1 (byte 0)
        let keyOne = Hkdf.expand initialKey salt info 32
        let keyTwo = Hkdf.expand initialKey saltTwo info 32
        Assert.That(keyOne.Length, Is.EqualTo(32))
        Assert.That(keyTwo.Length, Is.EqualTo(32))
        Assert.That(keyOne.SequenceEqual(keyTwo), Is.False)
       