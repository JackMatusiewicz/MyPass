module Aes

open Streams
open System.IO
open System.Security.Cryptography
open System.Text

let private keySizeBits = 256
let private keySizeBytes = 32

type Salt = Salt of string
type PassPhrase = PassPhrase of string

//Todo - look at making this private
type AesKey = {
    Key : byte[]
}

let private hash (data : string) =
    use sha256 = new SHA256Managed()
    sha256.ComputeHash(Encoding.UTF8.GetBytes(data))

let private createAes () =
    let aes = new AesManaged()
    aes.KeySize <- 256
    aes

let newKey () =
    use aes = createAes ()
    {Key = aes.Key}

let generateFromPassPhrase (salt : Salt) (phrase : PassPhrase) =
    let (Salt saltData) = salt
    let (PassPhrase text) = phrase
    use deriver = new Rfc2898DeriveBytes(text, hash saltData, 1000)
    let keyBytes = deriver.GetBytes(keySizeBytes)
    {Key = keyBytes}

let createEncryptionStream (key : AesKey) (data : Stream) : CryptoStream =
    use aes = createAes ()
    aes.GenerateIV()
    aes.Key <- key.Key
    let encryptor = aes.CreateEncryptor(aes.Key, aes.IV)
    let cs = new CryptoStream(data, encryptor, CryptoStreamMode.Write)
    let los = new LeaveOpenStream(cs)
    use bw = new BinaryWriter(los)
    bw.Write(aes.IV)
    cs

let encrypt (key : AesKey) (data : byte[]) : byte[] =
    let writeDataToStream (data : byte[]) : MemoryStream = 
        let ms = new MemoryStream()
        use encryptionStream = createEncryptionStream key ms
        use writer = new BinaryWriter(encryptionStream)
        writer.Write(data)
        ms

    let outputDataStream = writeDataToStream data
    let cipherText = outputDataStream.ToArray()
    outputDataStream.Dispose()
    cipherText

let createDecryptionStream (key : AesKey) (data : Stream) : CryptoStream =
    use aes = createAes ()
    aes.GenerateIV()
    aes.Key <- key.Key
    let ivBytes = Array.create (aes.IV.Length) (byte 0)
    data.Read(ivBytes, 0, aes.IV.Length) |> ignore
    let decryptor = aes.CreateDecryptor(aes.Key, ivBytes)
    new CryptoStream(data, decryptor, CryptoStreamMode.Read)

let decrypt (key : AesKey) (data : byte[]) : byte[] =
    let ms = new MemoryStream(data)
    use decryptionStream = createDecryptionStream key ms
    use sr = new StreamReader(decryptionStream)
    let stringData = sr.ReadToEnd()
    decryptionStream.Dispose()
    Encoding.UTF8.GetBytes(stringData)