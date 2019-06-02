namespace MyPass.Tests

open NUnit.Framework
open MyPass

module TupleTests =

    let rec private generateDifferentPassword (pw : string) (genPass : unit -> string) : string =
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

    [<Test>]
    let ``Given a function that fails, when traverse is used, then correct result is returned`` () =
        let f = fun x -> if x % 2 = 0 then Failure "even" else Success "odd"
        let x = (5,4)

        match Tuple.traverse f x with
        | Failure f -> Assert.That (f, Is.EqualTo ("even"))
        | Success s -> Assert.Fail ()

    [<Test>]
    let ``lmap works correctly`` () =
        let x = (5,3)
        let add10 = (+) 10
        let x = Tuple.lmap add10 x
        Assert.That(x, Is.EqualTo(15,3))