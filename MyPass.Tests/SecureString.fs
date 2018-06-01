namespace MyPass.Tests

open System.Security

module SecureString =

    let fromString (s : string) : SecureString =
        let cs = s.ToCharArray ()
        let ss = new SecureString ()
        cs |> Array.iter ss.AppendChar
        ss