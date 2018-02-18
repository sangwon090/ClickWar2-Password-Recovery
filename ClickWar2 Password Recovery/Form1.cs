using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace ClickWar2_Password_Recovery
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                using (RegistryKey registry = Registry.CurrentUser.OpenSubKey("ClickWar2"))
                {
                    if (registry == null)
                    {
                        MessageBox.Show("ClickWar2 계정 정보 저장 이력이 없습니다.", "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Application.Exit();
                    }
                    else
                    {
                        if(registry.GetValue("LoginPass") == null || registry.GetValue("LoginKey") == null)
                        {
                            MessageBox.Show("LoginPass 또는 LoginKey의 값이 null입니다.", "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            Application.Exit();
                        }
                        else
                        {
                            string data = (string) registry.GetValue("LoginPass");
                            string key = (string) registry.GetValue("LoginKey");

                            RijndaelManaged aes = new RijndaelManaged();
                            aes.KeySize = 256;
                            aes.BlockSize = 128;
                            aes.Mode = CipherMode.CBC;
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Key = Enumerable.Range(0, key.Length)
                                .Where(x => x % 2 == 0)
                                .Select(x => Convert.ToByte(key.Substring(x, 2), 16))
                                .ToArray();
                            aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                            var decryptor = aes.CreateDecryptor();
                            byte[] buffer = null;
                            using(var mStream = new MemoryStream())
                            {
                                using (var cStream = new CryptoStream(mStream, decryptor, CryptoStreamMode.Write))
                                {
                                    byte[] xStr = Convert.FromBase64String(data);
                                    cStream.Write(xStr, 0, xStr.Length);
                                }

                                buffer = mStream.ToArray();
                            }

                            textBox1.Text = Encoding.UTF8.GetString(buffer);
                        }
                    }
                }
            }
            catch (Exception err)
            {
                MessageBox.Show(err.ToString(), "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(textBox1.Text);
        }
    }
}
