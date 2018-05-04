namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result
open System.IO.Abstractions

module FileKeyTests =

    [<Test>]
    [<Repeat(10000)>]
    let ``When a file key is generated then it has the correct properties`` () =
        let (FileKey key) = FileKey.generateFileKey()
        Assert.That(key.Length, Is.EqualTo(16))
        let containsCorrectCharacters =
                Array.fold
                    (fun b c -> b && (Array.contains c FileKey.availableCharacters))
                    true
                    (key.ToCharArray())
        Assert.That(containsCorrectCharacters, Is.True)

    [<Test>]
    let ``Given a file key, when key is extracted from object, then correct value returned`` () =
        let pw = Password.createPassword 10u
        let fk = FileKey pw
        let pw2 = FileKey.getKey fk

        Assert.That(pw, Is.EqualTo pw2)

    [<Test>]
    let ``Given an invalid directory, when try to create file key, then error is returned`` () =
        let path = System.IO.Directory.GetCurrentDirectory ()
        let file = System.IO.Path.Combine (path, "ThisFileWillNotExist.txt")
        let key = FileKey.read (FileSystem ()) file
        match key with
        | Success _ -> Assert.Fail ()
        | Failure msg -> Assert.That (msg.Contains ("Could not find file"), Is.True)