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

        Assert.That (FailReason.toString a, Is.EqualTo ("test was an invalid url"))
        Assert.That (FailReason.toString b, Is.EqualTo ("test already exists"))
        Assert.That (FailReason.toString c, Is.EqualTo ("test was not found"))
        Assert.That (FailReason.toString d, Is.EqualTo ("test is not a valid MyPass command"))
        Assert.That (FailReason.toString e, Is.EqualTo ("Invalid choice: test"))