namespace MyPass

/// Head always points at the next free slot
type 'a CircularBuffer = {
    Buffer : 'a option []
    Head : int
}

module CircularBuffer =

    let make<'a> (capacity : int) =
        let (buffer : 'a option []) = Array.init capacity (fun i -> None)

        {
            Buffer = buffer
            Head = 0
        }

    let add (item : 'a) (buffer : 'a CircularBuffer) : 'a CircularBuffer =
        buffer.Buffer.[buffer.Head] <- Some item

        {
            Buffer = buffer.Buffer
            Head = if buffer.Head = buffer.Buffer.Length - 1 then 0 else buffer.Head + 1
        }

    let getAll (buffer : 'a CircularBuffer) : 'a [] =
        let rec fill (oldBuffer : 'a option []) (startIndex : int) (currentIndex : int) (accIndex : int) (acc : 'a []) : 'a [] =
            match oldBuffer.[currentIndex] with
            | None -> acc
            | Some v ->
                acc.[accIndex] <- v
                let nextIndex = if currentIndex + 1 = oldBuffer.Length then 0 else currentIndex + 1
                if nextIndex = startIndex then
                    acc
                else
                    fill oldBuffer startIndex nextIndex (accIndex + 1) acc

        let filled = Array.sumBy (function | None -> 0 | Some _ -> 1) buffer.Buffer
        let returnBuffer = Array.init filled (fun _ -> Unchecked.defaultof<'a>)
        let startIndex = if buffer.Head - 1 < 0 then buffer.Buffer.Length - 1 else buffer.Head - 1
        fill buffer.Buffer startIndex startIndex 0 returnBuffer