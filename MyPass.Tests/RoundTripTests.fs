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
        let currentDir = TestContext.CurrentContext.TestDirectory
        match FileKey.read fs (Path.Combine (currentDir, "FileKey.fk")) with
        | Result.Failure f ->
            Assert.Fail ()
        | Result.Success fk ->
            let userName = "test"
            let passPhrase = SecureString.fromString "test"
            let vaultPath = Path.Combine (currentDir, "TestVault.vt")

            let fileKeyBytes = FileKey.toBytes fk
            let key =
                MasterKey.make
                    "Version1.0"
                    fileKeyBytes
                    userName
                    passPhrase

            let manager = fs.File.ReadAllBytes vaultPath
            match Vault.decrypt key manager with
            | Result.Failure a -> Assert.Fail ()
            | Result.Success _ -> Assert.Pass ()