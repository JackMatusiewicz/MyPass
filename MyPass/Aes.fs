namespace MyPass

open System.IO
open System.Security.Cryptography
open System.Text

[<Struct>]
type Salt = Salt of string

[<Struct>]
type PassPhrase = PassPhrase of string

//Todo - look at making this private
type AesKey = {
    Key : byte[]
}

module Aes =

    let private keySizeBits = 256
    let private keySizeBytes = keySizeBits / 8

    let private hash (data : string) =
        use sha256 = new SHA256Managed()
        sha256.ComputeHash(Encoding.UTF8.GetBytes(data))

    let private makeKey () =
        let aes = new AesManaged ()
        aes.KeySize <- keySizeBits
        aes

    let make () =
        use aes = makeKey ()
        {Key = aes.Key}

    let generateFromPassPhrase (salt : Salt) (phrase : PassPhrase) =
        let (Salt saltData) = salt
        let (PassPhrase text) = phrase
        use deriver = new Rfc2898DeriveBytes(text, hash saltData, 1000)
        let keyBytes = deriver.GetBytes(keySizeBytes)
        {Key = keyBytes}

    let private createEncryptionStream (key : AesKey) (data : Stream) : CryptoStream =
        use aes = makeKey ()
        aes.GenerateIV()
        aes.Key <- key.Key
        let encryptor = aes.CreateEncryptor(aes.Key, aes.IV)
        let cs = new CryptoStream(data, encryptor, CryptoStreamMode.Write)
        use bw = new BinaryWriter(cs, System.Text.Encoding.UTF8, true)
        bw.Write(aes.IV)
        cs

    let encrypt (key : AesKey) (data : byte[]) : byte[] =
        let writeDataToStream (data : byte[]) : MemoryStream = 
            let ms = new MemoryStream()
            use encryptionStream = createEncryptionStream key ms
            use writer =
                new BinaryWriter(
                    encryptionStream,
                    System.Text.Encoding.UTF8,
                    true)
            writer.Write(data)
            ms

        let outputDataStream = writeDataToStream data
        let cipherText = outputDataStream.ToArray()
        outputDataStream.Dispose()
        cipherText

    let private createDecryptionStream (key : AesKey) (data : Stream) : CryptoStream =
        use aes = makeKey ()
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