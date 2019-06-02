namespace MyPass.Tests

open NUnit.Framework
open MyPass
open MyPass.Result.Operators

module ResultTests =

    let functorCases =
        [
            (Success 5, Success "5")
            (Failure "Sad", Failure "Sad")
        ] |> List.map (fun (a,b) -> TestCaseData(a,b))

    [<Test>]
    [<TestCaseSource("functorCases")>]
    let ``Mapping to string over a result context returns correct result.`` (input, output) =
        let toString = fun o -> o.ToString()
        let res = toString <!> input
        Assert.That(res, Is.EqualTo(output))

    let applicativeCases =
        [
            (Success 2, Success 3, Success 5)
            (Success 2, Failure "Sad", Failure "Sad")
            (Failure "Sad", Success 3, Failure "Sad")
            (Failure "Sad", Failure "Happy", Failure "Sad")
        ] |> List.map (fun (a,b,c) -> TestCaseData(a,b,c))

    [<Test>]
    [<TestCaseSource("applicativeCases")>]
    let ``Applicative over result contexts returns correct result.`` (a,b, output) =
        let res = Result.lift (+) <*> a <*> b
        Assert.That(res, Is.EqualTo(output))

    let cleanDivide (a : int) : Result<string, int> =
        if a % 2 = 0 then
            Success <| a / 2
        else Failure "Odd number"

    let monadCases =
        [
            (4, Success 1)
            (3, Failure "Odd number")
            (6, Failure "Odd number")
        ] |> List.map (fun (a,b) -> TestCaseData(a,b))

    [<Test>]
    [<TestCaseSource("monadCases")>]
    let ``Running monadic function returns correct result`` (a, output) =
        let res = (cleanDivide a) >>= cleanDivide
        Assert.That(res, Is.EqualTo(output))

    [<Test>]
    let ``Given a function to run when result is successful then it runs``() =
        let mutable set = false
        let setFunc = fun _ -> set <- true
        let x = Result.lift 5
        x |> Result.iter setFunc
        Assert.That(set, Is.True)

    [<Test>]
    let ``Given a function to run when result is unsuccessful then it doesn't run``() =
        let mutable set = false
        let setFunc = fun _ -> set <- true
        let x = Failure "nope"
        x |> Result.iter setFunc
        Assert.That(set, Is.False)