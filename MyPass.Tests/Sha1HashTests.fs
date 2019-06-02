namespace MyPass.Tests

open NUnit.Framework
open MyPass

module Sha1HashTests =

    [<Test>]
    [<TestCase("hello")>]
    [<TestCase("5BAA61E4C9B93[3F0682250B6CF8331B7EE68FD8")>]
    let ``Given invalid sha1 hex string, when made into Sha1Hash, then failure returned`` (s : string) =
        match Sha1Hash.fromString s with
        | Failure f -> Assert.That (f, Is.EqualTo (InvalidSha1Hash))
        | Success _ -> Assert.Fail ("Expected to fail")

    [<Test>]
    let ``Given a valid sha1 hash hex string, when turned into a hash, then it succeeds`` () =
        let hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        match Sha1Hash.fromString hash with
        | Failure f -> Assert.Fail ("Expected to succeed")
        | Success _ -> Assert.Pass ()