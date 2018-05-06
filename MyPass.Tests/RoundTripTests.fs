namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq
open System.IO.Abstractions

module RoundTripTests =

    let ``Given vault and file key, when correct details are provided, then vault is decrypted.`` () =
        let fs = new FileSystem ()
        match FileKey.read fs "FileKey.fk" with
        | Result.Failure _ -> Assert.Fail ()
        | Result.Success fk ->
            let userName = "test"
            let passPhrase = "test"
            let vaultPath = "TestVault.vt"

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