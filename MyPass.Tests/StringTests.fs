namespace MyPass.Tests

open NUnit.Framework
open MyPass

module StringTests =

    [<Test>]
    let ``Given a list of characters when converted to string then string is correct``() =
        let data = ['a'; 'b'; 'c'] |> String.ofList
        Assert.That(data, Is.EqualTo("abc"))

    [<Test>]
    let ``Given a empty list of characters when converted to string then string is correct``() =
        let data = [] |> String.ofList
        Assert.That(data, Is.EqualTo(""))