namespace MyPass.Tests

open NUnit.Framework
open MyPass

module AppendOnlyRingBufferTests =

    [<Test>]
    let ``When exact amount of data to fill buffer is inserted, then get returns correct list`` () =
        let buffer = AppendOnlyRingBuffer.make 5
        let fullBuffer =
            buffer
            |> AppendOnlyRingBuffer.add 1
            |> AppendOnlyRingBuffer.add 2
            |> AppendOnlyRingBuffer.add 3
            |> AppendOnlyRingBuffer.add 4
            |> AppendOnlyRingBuffer.add 5
        let data = AppendOnlyRingBuffer.get fullBuffer
        Assert.That(data, Is.EqualTo([|1;2;3;4;5|]))

    [<Test>]
    let ``When data overflows buffer, then get returns correct list`` () =
        let buffer = AppendOnlyRingBuffer.make 5
        let fullBuffer =
            buffer
            |> AppendOnlyRingBuffer.add 1
            |> AppendOnlyRingBuffer.add 2
            |> AppendOnlyRingBuffer.add 3
            |> AppendOnlyRingBuffer.add 4
            |> AppendOnlyRingBuffer.add 5
            |> AppendOnlyRingBuffer.add 6
            |> AppendOnlyRingBuffer.add 7
            |> AppendOnlyRingBuffer.add 8
        let data = AppendOnlyRingBuffer.get fullBuffer
        Assert.That(data, Is.EqualTo([|4;5;6;7;8|]))