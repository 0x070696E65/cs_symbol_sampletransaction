using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Numerics;
using System.Globalization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using System.Net.Http;
using System.Net.Http.Headers;

namespace CsSymbolSampleTransaction
{
    class Program
    {
        static void Main(string[] args)
        {
            // アカウント作成
            var privateKey = Utils.RandomBytes(32);
            var publicKey = new Ed25519PrivateKeyParameters(privateKey, 0).GeneratePublicKey().GetEncoded();
            Console.WriteLine(Utils.ToHex(privateKey));
            Console.WriteLine(Utils.ToHex(publicKey));

            // アカウント復元
            var alicePrivateKey = Utils.GetBytes("PRIVATE_KEY");
            var alicePublicKey = new Ed25519PrivateKeyParameters(alicePrivateKey, 0).GeneratePublicKey().GetEncoded();
            Console.WriteLine(Utils.ToHex(alicePrivateKey));
            Console.WriteLine(Utils.ToHex(alicePublicKey));

            // 公開鍵からのアドレス導出
            var addressHasher = new Sha3Digest(256);
            var publicKeyHash = new byte[addressHasher.GetDigestSize()];
            addressHasher.BlockUpdate(alicePublicKey, 0, alicePublicKey.Length);
            addressHasher.DoFinal(publicKeyHash, 0);
            var addressBodyHasher = new RipeMD160Digest();
            var addressBody = new byte[addressBodyHasher.GetDigestSize()];
            addressBodyHasher.BlockUpdate(publicKeyHash, 0, publicKeyHash.Length);
            addressBodyHasher.DoFinal(addressBody, 0);
            var sumHasher = new Sha3Digest(256);
            var preSumHash = new byte[sumHasher.GetDigestSize()];
            sumHasher.BlockUpdate(Utils.GetBytes("98" + Utils.ToHex(addressBody)), 0, 21);
            sumHasher.DoFinal(preSumHash, 0);
            var sumHash = new byte[3];
            Array.Copy(preSumHash, sumHash, 3);
            var aliceAddress = Base32.ToBase32String(Utils.GetBytes("98" + Utils.ToHex(addressBody) + Utils.ToHex(sumHash))).Substring(0, 39);
            Console.WriteLine(aliceAddress);

            // トランザクション構築
            var version = new byte[] { 1 };
            var networkType = new byte[] { 152 };
            var transactionType = BitConverter.GetBytes((ushort)16724);
            var fee = BitConverter.GetBytes((ulong)16000);
            var deadline = BitConverter.GetBytes((ulong)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds + 7200 - 1637848847) * 1000);
            var recipientAddress = Base32.FromBase32String("ADDRESS");
            var mosaicCount = new byte[] { 1 };
            var mosaicId = BitConverter.GetBytes((ulong)BigInteger.Parse("3A8416DB2D53B6C8", NumberStyles.HexNumber));
            var mosaicAmount = BitConverter.GetBytes((ulong)100);
            var messageStr = "Hello Symbol!";
            var message = Encoding.UTF8.GetBytes(messageStr.Replace("-", ""));
            var messageSize = BitConverter.GetBytes((ushort)(Encoding.UTF8.GetBytes(messageStr).Length + 1));

            // トランザクション署名
            var verifiableBody = Utils.ToHex(version)
                + Utils.ToHex(networkType)
                + Utils.ToHex(transactionType)
                + Utils.ToHex(fee)
                + Utils.ToHex(deadline)
                + Utils.ToHex(recipientAddress)
                + Utils.ToHex(messageSize)
                + Utils.ToHex(mosaicCount)
                + "00" + "00000000"
                + Utils.ToHex(mosaicId)
                + Utils.ToHex(mosaicAmount)
                + "00" + Utils.ToHex(message);

            var verifiableString = "7fccd304802016bebbcd342a332f91ff1f3bb5e902988b352697be245f48e836"
                + verifiableBody;

            var verifiableBuffer = Utils.GetBytes(verifiableString);
            var signer = new Ed25519Signer();
            signer.Init(true, new Ed25519PrivateKeyParameters(alicePrivateKey, 0));
            signer.BlockUpdate(verifiableBuffer, 0, verifiableBuffer.Length);
            var signature = signer.GenerateSignature();
            
            // トランザクションの通知
            var transactionSize = BitConverter.GetBytes((uint)Utils.GetBytes(verifiableBody).Length + 108);

            var payloadString = Utils.ToHex(transactionSize)
                + "00000000"
                + Utils.ToHex(signature)
                + Utils.ToHex(alicePublicKey)
                + "00000000"
                + verifiableBody;

            var httpClient = new HttpClient();
            var payload = new StringContent("{ \"payload\" : \"" + payloadString + "\"}");
            payload.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            var response = httpClient.PutAsync("https://sym-test-02.opening-line.jp:3001/transactions", payload).Result;
            Console.WriteLine(response.Headers);
            Console.WriteLine(response.RequestMessage);

            var hashableBuffer = Utils.GetBytes(
                Utils.ToHex(signature)
                + Utils.ToHex(alicePublicKey)
                + verifiableString
                );

            var hasher = new Sha3Digest(256);
            var transactionHash = new byte[hasher.GetDigestSize()];
            hasher.BlockUpdate(hashableBuffer, 0, hashableBuffer.Length);
            hasher.DoFinal(transactionHash, 0);

            Console.WriteLine("transactionStatus: https://sym-test-02.opening-line.jp:3001/transactionStatus/" + Utils.ToHex(transactionHash));
            Console.WriteLine("confirmed: https://sym-test-02.opening-line.jp:3001/transactions/confirmed/" + Utils.ToHex(transactionHash));
            Console.WriteLine("explorer: https://testnet.symbol.fyi/transactions/" + Utils.ToHex(transactionHash));
        }
    }

    class Utils
    {
        internal static byte[] GetBytes(string hexString)
        {
            var bs = new List<byte>();
            for (var i = 0; i < hexString.Length / 2; i++)
            {
                bs.Add(Convert.ToByte(hexString.Substring(i * 2, 2), 16));
            }
            return bs.ToArray();
        }

        internal static byte[] RandomBytes(byte length)
        {
            var rngCsp = new RNGCryptoServiceProvider();
            var randomBytes = new byte[length];
            rngCsp.GetBytes(randomBytes);
            return randomBytes;
        }

        internal static string ToHex(byte[] bytes)
        {
            var str = BitConverter.ToString(bytes);
            str = str.Replace("-", string.Empty);
            return str;
        }
    }

    static class Base32
    {
        private static readonly char[] _digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();
        private const int _mask = 31;
        private const int _shift = 5;

        internal static int CharToInt(char c)
        {
            switch (c)
            {
                case 'A': return 0;
                case 'B': return 1;
                case 'C': return 2;
                case 'D': return 3;
                case 'E': return 4;
                case 'F': return 5;
                case 'G': return 6;
                case 'H': return 7;
                case 'I': return 8;
                case 'J': return 9;
                case 'K': return 10;
                case 'L': return 11;
                case 'M': return 12;
                case 'N': return 13;
                case 'O': return 14;
                case 'P': return 15;
                case 'Q': return 16;
                case 'R': return 17;
                case 'S': return 18;
                case 'T': return 19;
                case 'U': return 20;
                case 'V': return 21;
                case 'W': return 22;
                case 'X': return 23;
                case 'Y': return 24;
                case 'Z': return 25;
                case '2': return 26;
                case '3': return 27;
                case '4': return 28;
                case '5': return 29;
                case '6': return 30;
                case '7': return 31;
            }

            return -1;
        }

        internal static byte[] FromBase32String(string encoded)
        {
            if (encoded == null)
                throw new ArgumentNullException(nameof(encoded));

            // Remove whitespace and padding. Note: the padding is used as hint 
            // to determine how many bits to decode from the last incomplete chunk
            // Also, canonicalize to all upper case
            encoded = encoded.Trim().TrimEnd('=').ToUpper();
            if (encoded.Length == 0)
                return new byte[0];

            var outLength = encoded.Length * _shift / 8;
            var result = new byte[outLength];
            var buffer = 0;
            var next = 0;
            var bitsLeft = 0;
            var charValue = 0;
            foreach (var c in encoded)
            {
                charValue = CharToInt(c);
                if (charValue < 0)
                    throw new FormatException("Illegal character: `" + c + "`");

                buffer <<= _shift;
                buffer |= charValue & _mask;
                bitsLeft += _shift;
                if (bitsLeft >= 8)
                {
                    result[next++] = (byte)(buffer >> (bitsLeft - 8));
                    bitsLeft -= 8;
                }
            }

            return result;
        }

        internal static string ToBase32String(byte[] data, bool padOutput = false)
        {
            return ToBase32String(data, 0, data.Length, padOutput);
        }

        internal static string ToBase32String(byte[] data, int offset, int length, bool padOutput = false)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset));

            if (length < 0)
                throw new ArgumentOutOfRangeException(nameof(length));

            if ((offset + length) > data.Length)
                throw new ArgumentOutOfRangeException();

            if (length == 0)
                return "";

            // SHIFT is the number of bits per output character, so the length of the
            // output is the length of the input multiplied by 8/SHIFT, rounded up.
            // The computation below will fail, so don't do it.
            if (length >= (1 << 28))
                throw new ArgumentOutOfRangeException(nameof(data));

            var outputLength = (length * 8 + _shift - 1) / _shift;
            var result = new StringBuilder(outputLength);

            var last = offset + length;
            int buffer = data[offset++];
            var bitsLeft = 8;
            while (bitsLeft > 0 || offset < last)
            {
                if (bitsLeft < _shift)
                {
                    if (offset < last)
                    {
                        buffer <<= 8;
                        buffer |= (data[offset++] & 0xff);
                        bitsLeft += 8;
                    }
                    else
                    {
                        int pad = _shift - bitsLeft;
                        buffer <<= pad;
                        bitsLeft += pad;
                    }
                }

                int index = _mask & (buffer >> (bitsLeft - _shift));
                bitsLeft -= _shift;
                result.Append(_digits[index]);
            }

            if (padOutput)
            {
                int padding = 8 - (result.Length % 8);
                if (padding > 0) result.Append('=', padding == 8 ? 0 : padding);
            }

            return result.ToString();
        }
    }
}
