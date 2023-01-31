/*
 * ------------------------------------------------------------
 * "THE BEERWARE LICENSE" (Revision 42):
 * <d@tenpir.at> wrote this code. As long as you retain this 
 * notice, you can do whatever you want with this stuff. If we
 * meet someday, and you think this stuff is worth it, you can
 * buy me a beer in return.
 * ------------------------------------------------------------
 */

using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO.Compression;
using System.IO;

namespace RIJSecureStore
{
    class SecureStore
    {
        AES aes = new AES();
        ZIP zip;

        private string password = "";
        private string filename = "";

        public SecureStore()
        {
            this.filename = "store";
            zip = new ZIP(this.filename);
            this.password = "1234567890";
        }

        public SecureStore(string Filename, string Password)
        {
            this.filename = Filename;
            zip = new ZIP(this.filename);
            this.password = Password;
        }

        public string Filename { get { return this.Filename; } set { this.filename = value; this.zip = new ZIP(this.filename); } }
        public string Password { get { return this.password; } set { this.password = value; } } // TODO SecureString

        public void SetObject(string Name, string Value)
        {
            byte[] encrypted = aes.Encrypt(Value, this.password);
            zip.UpdateEntry(Name, encrypted,true);

        }

        public string GetObject(string Name)
        {
            byte[] data = zip.ReadEntry(Name);
            return aes.DecryptString(data, this.password);

        }

        public void RemoveObject(string Name)
        {
            zip.DeleteEntry(Name);
        }

        public string[] GetAllObjects()
        {
            return zip.GetAllEntries();
        }
    }
    class ZIP
    {
        private string filename = "";
        private string entryPrefix = "data/";
        public ZIP(string Filename)
        {
            this.filename = Filename;
            if (!File.Exists(this.filename))
            {
                var archive = ZipFile.Open(this.filename, ZipArchiveMode.Create, Encoding.UTF8);
                archive.Dispose();
            }
        }

        public void CreateEntry(string EntryName)
        {
            string Name = entryPrefix + EntryName;
            var archive = ZipFile.Open(this.filename, ZipArchiveMode.Update, Encoding.UTF8);
            var entry = archive.GetEntry(Name);
            if (entry == null)
            {
                archive.CreateEntry(Name);
                entry = archive.GetEntry(Name);
            }
            archive.Dispose();
        }

        public void UpdateEntry(string EntryName, byte[] Value)
        {
            UpdateEntry(EntryName, Value, false);
        }

        public void UpdateEntry(string EntryName, byte[] Value, bool CreateIfNotExistent)
        {
            string Name = entryPrefix + EntryName;
            var archive = ZipFile.Open(this.filename, ZipArchiveMode.Update, Encoding.UTF8);
            var entry = archive.GetEntry(Name);
            if (entry == null && CreateIfNotExistent)
            {
                archive.CreateEntry(Name);
                entry = archive.GetEntry(Name);
            }
            using (var stream = entry.Open())
            {
                stream.SetLength(Value.Length);
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    writer.Write(Value);
                }
            }
            archive.Dispose();
        }

        public byte[] ReadEntry(string EntryName)
        {
            string Name = entryPrefix + EntryName;
            byte[] result = new byte[1];

            var archive = ZipFile.Open(this.filename, ZipArchiveMode.Read);
            var entry = archive.GetEntry(Name);

            using (BinaryReader reader = new BinaryReader(entry.Open()))
            {
                result = ReadAllBytes(reader);
            }
            archive.Dispose();
            return result;
        }

        public string[] GetAllEntries()
        {
            List<string> result = new List<string>();
            var archive = ZipFile.Open(this.filename, ZipArchiveMode.Read);
            foreach (var e in archive.Entries)
            {
                if (e.FullName.StartsWith(entryPrefix))
                    result.Add(e.Name);
            }
            archive.Dispose();
            return result.ToArray();
        }

        public void DeleteEntry(string EntryName)
        {
            string Name = entryPrefix + EntryName;
            var archive = ZipFile.Open(this.filename, ZipArchiveMode.Update);
            var entry = archive.GetEntry(Name);
            entry.Delete();
            archive.Dispose();
        }

        private byte[] ReadAllBytes(BinaryReader reader)
        {
            const int bufferSize = 4096;
            using (var ms = new MemoryStream())
            {
                byte[] buffer = new byte[bufferSize];
                int count;
                while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
                    ms.Write(buffer, 0, count);
                return ms.ToArray();
            }

        }

    }
    class AES
    {
        private int KeySize = 256;
        private int BlockSize = 128;
        private CipherMode CipherMode = CipherMode.CBC;

        private byte[] GenerateSalt(int MaximumSaltLength)
        {
            var salt = new byte[MaximumSaltLength];
            using (var random = new RNGCryptoServiceProvider())
            {
                random.GetNonZeroBytes(salt);
            }

            return salt;
        }

        public byte[] Encrypt(string StringToBeEncrypted, string PasswordString)
        {
            return Encrypt(System.Text.Encoding.UTF8.GetBytes(StringToBeEncrypted), System.Text.Encoding.UTF8.GetBytes(PasswordString));
        }

        public byte[] Encrypt(byte[] BytesToBeEncrypted, string PasswordString)
        {
            return Encrypt(BytesToBeEncrypted, System.Text.Encoding.UTF8.GetBytes(PasswordString));
        }

        public byte[] Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte SaltLength = 16;
            byte[] encryptedBytes = null;
            byte[] saltBytes = GenerateSalt(SaltLength);

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = this.KeySize;
                    AES.BlockSize = this.BlockSize;
                    AES.Mode = this.CipherMode;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);



                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            byte[] result = new byte[1 + saltBytes.Length + encryptedBytes.Length];
            result[0] = SaltLength;
            System.Buffer.BlockCopy(saltBytes, 0, result, 1, saltBytes.Length);
            System.Buffer.BlockCopy(encryptedBytes, 0, result, saltBytes.Length + 1, encryptedBytes.Length);
            return result;
        }


        public string DecryptString(byte[] bytesToBeDecrypted, string PasswordString)
        {
            return System.Text.Encoding.UTF8.GetString(Decrypt(bytesToBeDecrypted, System.Text.Encoding.UTF8.GetBytes(PasswordString)));

        }

        public byte[] Decrypt(byte[] bytesToBeDecrypted, string PasswordString)
        {
            return Decrypt(bytesToBeDecrypted, System.Text.Encoding.UTF8.GetBytes(PasswordString));
        }

        public byte[] Decrypt(byte[] BytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;
            byte SaltSize = BytesToBeDecrypted[0];

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = this.KeySize;
                    AES.BlockSize = this.BlockSize;
                    AES.Mode = this.CipherMode;

                    byte[] saltBytes = new byte[SaltSize];
                    byte[] encryptedBytes = new byte[BytesToBeDecrypted.Length - (SaltSize + 1)];

                    System.Buffer.BlockCopy(BytesToBeDecrypted, 1, saltBytes, 0, SaltSize);
                    System.Buffer.BlockCopy(BytesToBeDecrypted, SaltSize + 1, encryptedBytes, 0, BytesToBeDecrypted.Length - (SaltSize + 1));

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedBytes, 0, encryptedBytes.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }


        public void EncryptFile(string filename, string outfilename, string psw)
        {
            string file = filename;
            string password = psw;

            byte[] bytesToBeEncrypted = File.ReadAllBytes(file); //read bytes to encrypt them 
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password); //read with UTF8 encoding the password.
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes); //hash the psw

            byte[] bytesEncrypted = Encrypt(bytesToBeEncrypted, passwordBytes);

            string fileEncrypted = outfilename;

            File.WriteAllBytes(fileEncrypted, bytesEncrypted);
        }

        public void DecryptFile(string filename, string outfilename, string psw)
        {
            string fileEncrypted = filename;
            string password = psw;

            byte[] bytesToBeDecrypted = File.ReadAllBytes(fileEncrypted);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = Decrypt(bytesToBeDecrypted, passwordBytes);

            string file = outfilename;
            File.WriteAllBytes(file, bytesDecrypted);
        }
    }
}
