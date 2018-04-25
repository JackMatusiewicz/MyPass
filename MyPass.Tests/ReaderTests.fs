namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Reader

module ReaderTests =

    [<Test>]
    let ``Given a number, when applied to a function, then the result is correct`` () =
        let f = (+) 5
        let g = (*) 2
        let h = (+) <-| f <~| g
        let result = h 3
        Assert.That(result, Is.EqualTo(14))