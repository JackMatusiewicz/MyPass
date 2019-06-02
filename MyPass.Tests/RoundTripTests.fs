namespace MyPass.Tests

open NUnit.Framework
open MyPass
open System.IO
open System.IO.Abstractions
open Hedgehog

module RoundTripTests =

    [<Test>]
    let ``Given vault and file key, when correct details are provided, then vault is decrypted.`` () =
        let fs = new FileSystem ()
        let currentDir = TestContext.CurrentContext.TestDirectory
        match FileKey.read fs (Path.Combine (currentDir, "FileKey.fk")) with
        | MyPass.Result.Failure _f ->
            Assert.Fail ()
        | MyPass.Result.Success fk ->
            let username = "test"
            let passPhrase = SecureString.fromString "test"
            let vaultPath = Path.Combine (currentDir, "TestVault.vt")

            let fileKeyBytes = FileKey.toBytes fk
            let key =
                MasterKey.make
                    "Version1.0"
                    fileKeyBytes
                    username
                    passPhrase

            let manager = fs.File.ReadAllBytes vaultPath
            match Vault.decrypt key manager with
            | MyPass.Result.Failure a -> Assert.Fail (FailReason.toString a)
            | MyPass.Result.Success _ -> Assert.Pass ()

    [<Test>]
    let ``Given a vault and all details except the right username, then the vault isn't decrypted`` () =
        property {
            let! username =
                Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                |> Gen.filter ((<>) "test")

            let fs = new FileSystem ()
            let currentDir = TestContext.CurrentContext.TestDirectory
            match FileKey.read fs (Path.Combine (currentDir, "FileKey.fk")) with
            | MyPass.Result.Failure _f ->
               return false
            | MyPass.Result.Success fk ->
                let passPhrase = SecureString.fromString "test"
                let vaultPath = Path.Combine (currentDir, "TestVault.vt")

                let fileKeyBytes = FileKey.toBytes fk
                let key =
                    MasterKey.make
                        "Version1.0"
                        fileKeyBytes
                        username
                        passPhrase

                let manager = fs.File.ReadAllBytes vaultPath
                match Vault.decrypt key manager with
                | MyPass.Result.Failure _ -> return true
                | MyPass.Result.Success _ -> return false
        } |> Property.check' 100<tests>

    [<Test>]
    let ``Given a vault and all details except the right password, then the vault isn't decrypted`` () =
        property {
            let! password =
                Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                |> Gen.filter ((<>) "test")

            let fs = new FileSystem ()
            let currentDir = TestContext.CurrentContext.TestDirectory
            match FileKey.read fs (Path.Combine (currentDir, "FileKey.fk")) with
            | MyPass.Result.Failure _f ->
               return false
            | MyPass.Result.Success fk ->
                let passPhrase = SecureString.fromString password
                let vaultPath = Path.Combine (currentDir, "TestVault.vt")

                let fileKeyBytes = FileKey.toBytes fk
                let key =
                    MasterKey.make
                        "Version1.0"
                        fileKeyBytes
                        "test"
                        passPhrase

                let manager = fs.File.ReadAllBytes vaultPath
                match Vault.decrypt key manager with
                | MyPass.Result.Failure _ -> return true
                | MyPass.Result.Success _ -> return false
        } |> Property.check' 100<tests>

    [<Test>]
    let ``Given a vault and all details except the right file key, then the vault isn't decrypted`` () =
        property {
            let fs = new FileSystem ()
            let currentDir = TestContext.CurrentContext.TestDirectory
            match FileKey.read fs (Path.Combine (currentDir, "FileKey.fk")) with
            | MyPass.Result.Failure _f ->
               return false
            | MyPass.Result.Success (FileKey fk) ->
                let! fileKey =
                    Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                    |> Gen.filter ((<>) fk)
                let passPhrase = SecureString.fromString "test"
                let vaultPath = Path.Combine (currentDir, "TestVault.vt")

                let fileKeyBytes = FileKey.toBytes (FileKey fileKey)
                let key =
                    MasterKey.make
                        "Version1.0"
                        fileKeyBytes
                        "test"
                        passPhrase

                let manager = fs.File.ReadAllBytes vaultPath
                match Vault.decrypt key manager with
                | MyPass.Result.Failure _ -> return true
                | MyPass.Result.Success _ -> return false
        } |> Property.check' 100<tests>

    [<Test>]
    let ``Given a vault and all details incorrect, then the vault isn't decrypted`` () =
        property {
            let fs = new FileSystem ()
            let currentDir = TestContext.CurrentContext.TestDirectory
            match FileKey.read fs (Path.Combine (currentDir, "FileKey.fk")) with
            | MyPass.Result.Failure _f ->
               return false
            | MyPass.Result.Success (FileKey fk) ->
                let! fileKey =
                    Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                    |> Gen.filter ((<>) fk)
                let! username =
                    Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                    |> Gen.filter ((<>) "test")
                let! password =
                    Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                    |> Gen.filter ((<>) "test")
                let passPhrase = SecureString.fromString password
                let vaultPath = Path.Combine (currentDir, "TestVault.vt")

                let fileKeyBytes = FileKey.toBytes (FileKey fileKey)
                let key =
                    MasterKey.make
                        "Version1.0"
                        fileKeyBytes
                        username
                        passPhrase

                let manager = fs.File.ReadAllBytes vaultPath
                match Vault.decrypt key manager with
                | MyPass.Result.Failure _ -> return true
                | MyPass.Result.Success _ -> return false
        } |> Property.check' 100<tests>