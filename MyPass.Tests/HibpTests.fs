namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open Result.Operators
open System.Linq

module HibpTests =

    //TODO - move test
    [<Test>]
    let ``Given a prefix that is too long, when HashPrefix is made then error is thrown`` () =
        let prefix = "123456"
        let hashPrefix = HashPrefix.make prefix
        match hashPrefix with
        | Success _ -> Assert.Fail ()
        | Failure f -> Assert.That (f, Is.EqualTo (InvalidHashPrefix))

    [<Test>]
    let ``Given a dummy finder, when I check if my password is on the list, then the correct outcome occurs`` () =
        let pe = {
                Secret = SecuredSecret.create "password" |> Secret
                Description = Description "My bing password"
                Name = Name "www.bing.com"
            }

        Vault.storePassword pe Vault.empty
        |> Result.map (fun v ->
            let data = "0043E8CC80EA715B31A294CFB2B1959A8FC:2\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:8\r\n03D6F047380D19641538F981DEDF2EBF810:2"
            let prefix = HashPrefix.make "5BAA6"
            let finder = fun _ -> Response <!> (Tuple.leftSequence (prefix, data))
            let findCompromise = Hibp.isCompromised finder
            let compromisedPws = Vault.getCompromisedPasswords findCompromise v
            match compromisedPws with
            | Failure f ->
                printfn "%s" <| FailReason.toString f
                Assert.Fail ()
            | Success (s::[]) ->
                Assert.That (s, Is.EqualTo (Name "www.bing.com"))
            | x ->
                printfn "OUTPUT NOT EXPECTED: %A" x
                Assert.Fail ())
        |> ignore