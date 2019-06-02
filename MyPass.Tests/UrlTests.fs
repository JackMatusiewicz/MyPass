namespace MyPass.Tests

open NUnit.Framework
open MyPass

module UrlTests =

    [<Test>]
    [<TestCase("sgdhdfj")>]
    [<TestCase("")>]
    [<TestCase("2")>]
    [<TestCase("www.google.com")>]
    let ``Given an invalid url, when a url is made, then error is returned`` (s : string) =
        let url = Url.make s
        match url with
        | Success s -> Assert.Fail ()
        | Failure _ -> Assert.Pass ()

    [<Test>]
    [<TestCase("https://google.com")>]
    [<TestCase("http://www.google.com")>]
    [<TestCase("http://google.com/42")>]
    let ``Given an valid url, when a url is made, then success is returned`` (s : string) =
        let url = Url.make s
        match url with
        | Success s -> Assert.Pass ()
        | Failure _ -> Assert.Fail ()