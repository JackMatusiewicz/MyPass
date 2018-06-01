namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq

module FailReasonTests =

    [<Test>]
    let ``Given a fail reason, when toString is called, then correct result is returned`` () =
        let a = InvalidUrl "test"
        let b = DuplicateEntry "test"
        let c = EntryNotFound "test"
        let d = InvalidCommand "test"
        let e = InvalidChoice "test"
        let f = InvalidResponseFormat
        let g = HttpRequestFailed 404

        Assert.That (FailReason.toString a, Is.EqualTo ("test was an invalid url"))
        Assert.That (FailReason.toString b, Is.EqualTo ("test already exists"))
        Assert.That (FailReason.toString c, Is.EqualTo ("test was not found"))
        Assert.That (FailReason.toString d, Is.EqualTo ("test is not a valid MyPass command"))
        Assert.That (FailReason.toString f, Is.EqualTo ("Data was in the wrong format"))
        Assert.That (FailReason.toString g, Is.EqualTo ("Received a failure error code: 404"))
        Assert.That (FailReason.toString InvalidHashPrefix, Is.EqualTo ("Hash prefix was not valid for the HaveIBeenPwned web service"))
        Assert.That (FailReason.toString InvalidSha1Hash, Is.EqualTo ("The value was an invalid sha1 hash"))