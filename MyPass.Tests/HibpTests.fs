namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq

module HibpTests =

    [<Test>]
    let ``Given a response, when deserialised, then results are correct`` () =
        let data = "0043E8CC80EA715B31A294CFB2B1959A8FC:2\r\n0119D4F6971D604B3242DA123FECC0C549B:8\r\n03D6F047380D19641538F981DEDF2EBF810:2"
        let hashes = Hibp.toHashes "21BD1" (Response data)

        let expected =
            [
                "21BD10043E8CC80EA715B31A294CFB2B1959A8FC"
                "21BD10119D4F6971D604B3242DA123FECC0C549B"
                "21BD103D6F047380D19641538F981DEDF2EBF810"
            ] |> Set.ofList

        Assert.That (hashes, Is.EqualTo expected)

    [<Test>]
    let ``Given a dummy finder, when I check if my password is on the list, then the correct outcome occurs`` () =
        let x = SecuredSecret.create "password"
        let data = "0043E8CC80EA715B31A294CFB2B1959A8FC:2\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:8\r\n03D6F047380D19641538F981DEDF2EBF810:2"
        let finder = fun _ -> Response data |> Success
        let matchFound = Hibp.checkForCompromise finder x
        match matchFound with
        | Failure _ -> Assert.Fail ()
        | Success s -> Assert.True (s)