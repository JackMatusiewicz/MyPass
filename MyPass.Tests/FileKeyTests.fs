﻿namespace MyPass.Tests

open NUnit.Framework
open MyPass
open System.IO.Abstractions
open System.Linq
open MyPass.SecureString

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
        let pw =
            Password.createPassword 10u
            |> fun p -> SecurePasswordHandler.Use(p, fun p -> String.fromBytes p)
        let fk = FileKey pw
        let pw2 = FileKey.getKey fk

        Assert.That(pw, Is.EqualTo pw2)

    [<Test>]
    let ``Given a file key, when key is extracted from object and converted to bytes, then correct value returned`` () =
        let fk = FileKey.generateFileKey ()
        let pw2 = FileKey.getKey fk |> System.Text.Encoding.UTF8.GetBytes

        Assert.That((FileKey.toBytes fk).SequenceEqual(pw2), Is.True)

    [<Test>]
    let ``Given an invalid directory, when try to create file key, then error is returned`` () =
        let path = System.IO.Directory.GetCurrentDirectory ()
        let file = System.IO.Path.Combine (path, "ThisFileWillNotExist.txt")
        let key = FileKey.read (FileSystem ()) file
        match key with
        | Success _ -> Assert.Fail ()
        | Failure msg -> Assert.Pass ()