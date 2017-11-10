namespace MyPass.Tests

open NUnit.Framework
open MyPass
open Result

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