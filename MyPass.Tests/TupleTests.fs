namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq

module TupleTests =

    let rec private generateDifferentPassword (pw : string) (genPass : unit -> string) : string =
        let len = pw.Length
        let newPass = genPass ()
        match newPass = pw with
        | true -> generateDifferentPassword pw genPass
        | false -> newPass

    [<Test>]
    let ``Simple tuple map test`` () =
        let tuple = (5, 7)
        let f = fun a -> a.ToString ()
        let r = Tuple.map f tuple
        Assert.That(r, Is.EqualTo (5, "7"))