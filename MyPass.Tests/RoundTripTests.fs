namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq
open System.IO
open System.IO.Abstractions

module RoundTripTests =

    [<Test>]
    let ``Given vault and file key, when correct details are provided, then vault is decrypted.`` () =
        let fs = new FileSystem ()
        let currentDir = Directory.GetCurrentDirectory ()
        match FileKey.read fs (Path.Combine (currentDir, "FileKey.fk")) with
        | Result.Failure _ -> Assert.Fail ()
        | Result.Success fk ->
            let userName = "test"
            let passPhrase = "test"
            let vaultPath = Path.Combine (currentDir, "TestVault.vt"))

            let fileKeyBytes = FileKey.toBytes fk
            let masterKey =
                Password.createMasterPassword
                    "Version1.0"
                    passPhrase
                    fileKeyBytes
                    userName
            let key = {Key = masterKey}

            let manager = fs.File.ReadAllBytes vaultPath
            match Vault.decryptManager key manager with
            | Result.Failure a -> Assert.Fail ()
            | Result.Success _ -> Assert.Pass ()