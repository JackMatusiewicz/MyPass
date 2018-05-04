namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.Linq
open System.IO
open System.IO.Abstractions

module ConsoleUiTests =

    [<Test>]
    [<Explicit("Currently failing")>]
    let ``Given a valid set of user data, when asked to create vault then vault is created`` () =
        let currentDir = Directory.GetCurrentDirectory()
        let testPath = Path.Combine (currentDir, "TestFolder")
        use td = new TemporaryDirectory (testPath)
        let vp = Path.Combine (testPath, "vault.v")
        let fkp = Path.Combine (testPath, "keyFile.kf")
        let ud = {
            VaultPath = vp
            FileKeyPath = fkp
            FileKey = FileKey.generateFileKey ()
            MasterPassPhrase = "test123"
            UserName = "TestUser" } |> ConsoleUi.makeUserData

        Assert.That(File.Exists(vp), Is.False)
        Assert.That(File.Exists(fkp), Is.False)
        let createdVault = ConsoleUi.constructVault (new FileSystem()) ud
        Assert.That(File.Exists(vp), Is.True)
        Assert.That(File.Exists(fkp), Is.True)