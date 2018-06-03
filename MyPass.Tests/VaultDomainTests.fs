namespace MyPass.Tests

open NUnit.Framework
open MyPass

module VaultDomainTests =

    [<Test>]
    let ``Given two names that are the same but with different cases, when checked for equal, then result is true`` () =
        let a = Name "bingbong"
        let b = Name "BINGBoNg"
        let r = a = b
        let r2 = a.Equals(b)
        Assert.True(r)
        Assert.True(r2)

    [<Test>]
    let ``Given two names that are the same but with different cases, when checked for comparison, then result is correct`` () =
        let a = Name "bingbong" :> System.IComparable<Name>
        let b = Name "BINGBoNg"
        let r = a.CompareTo(b)
        Assert.That(r, Is.Zero)

    [<Test>]
    let ``Given two different names, when compared, then result is expected`` () =
        let a = Name "bingbong" :> System.IComparable<Name>
        let b = Name "c"
        let r = a.CompareTo(b)
        Assert.That(r, Is.EqualTo(-1))