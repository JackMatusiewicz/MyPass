namespace MyPass.Tests

open NUnit.Framework
open MyPass
open System.IO
open System.IO.Abstractions
open Hedgehog

module RoundTripTests =

    let private fileKeyValue = "UZ7BRPZKZb9oFzrQ"

    let private decryptVault
        (username : string Gen)
        (password : string Gen)
        (fileKey : string Gen)
        : bool Gen
        =
        gen {
            let fs = new FileSystem ()
            let currentDir = TestContext.CurrentContext.TestDirectory
            let! fileKey = fileKey
            let! username = username
            let! password = password
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
        }

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
            let username =
                Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                |> Gen.filter ((<>) "test")

            let! result =
                decryptVault
                    username
                    (Gen.constant "test")
                    (Gen.constant fileKeyValue)
            return result
        } |> Property.check' 100<tests>

    [<Test>]
    let ``Given a vault and all details except the right password, then the vault isn't decrypted`` () =
        property {
            let password =
                Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                |> Gen.filter ((<>) "test")

            let! result =
                decryptVault
                    (Gen.constant "test")
                    password
                    (Gen.constant fileKeyValue)
            return result
        } |> Property.check' 100<tests>

    [<Test>]
    let ``Given a vault and all details except the right file key, then the vault isn't decrypted`` () =
        property {
            let fileKey =
                Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                |> Gen.filter ((<>) fileKeyValue)

            let! result =
                decryptVault
                    (Gen.constant "test")
                    (Gen.constant "test")
                    fileKey
            return result
        } |> Property.check' 100<tests>

    [<Test>]
    let ``Given a vault and all details incorrect, then the vault isn't decrypted`` () =
        property {
            let username =
                Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                |> Gen.filter ((<>) "test")
            let password =
                Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                |> Gen.filter ((<>) "test")
            let fileKey =
                Gen.string (Range.linear 3 30) (Gen.char 'a' 'Z')
                |> Gen.filter ((<>) fileKeyValue)

            let! result =
                decryptVault
                    username
                    password
                    fileKey
            return result
        } |> Property.check' 100<tests>