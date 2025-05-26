using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using Konscious.Security.Cryptography;
using System;
using System.Linq;
using Zxcvbn;
using System.Windows.Input;

namespace Lockr
{
    public partial class MainWindow : Window
    {
        private List<string> wordList = new List<string>();
        private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
        private const string SymbolCharsPassphrase = "!@#$%^&*()";
        private const double CapitalizationPercentage = 0.10;

        public MainWindow()
        {
            InitializeComponent();
            LoadWordlist();
            UpdatePasswordStrengthIndicator();
        }

        //new - kdf helper
        private byte[] DeriveKeyPbkdf2(string password, byte[] salt, int iterations, int keyLength)
        {
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                return deriveBytes.GetBytes(keyLength);
            }
        }

        private void LoadWordlist()
        {
            string wordlistFileName = "Wordlist.txt";
            string wordlistPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, wordlistFileName);

            try
            {
                if (File.Exists(wordlistPath))
                {
                    LoadWordlistFromFile(wordlistPath);
                }
                else
                {
                    // Fall back to embedded resource
                    LoadWordlistFromResource();
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "An unexpected error occurred loading the wordlist.";
                MessageBox.Show($"An error occurred: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                GeneratePassphraseButton.IsEnabled = false;
                PassphraseWordCountSlider.IsEnabled = false;
                PassphraseSeparator.IsEnabled = false;
            }
        }

        private void LoadWordlistFromFile(string path)
        {
            wordList = File.ReadAllLines(path)
                       .Select(line => Regex.Match(line, @"^\d+\s+(.+)$"))
                       .Where(match => match.Success)
                       .Select(match => match.Groups[1].Value.Trim())
                       .ToList();

            if (wordList.Count == 0)
            {
                StatusText.Text = "Wordlist loaded, but no words found (check format).";
                MessageBox.Show($"Wordlist seems empty or incorrectly formatted.", "Wordlist Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                LoadWordlistFromResource(); // Try embedded resource as fallback
            }
            else
            {
                StatusText.Text = $"Wordlist loaded from file ({wordList.Count} words). Ready.";
            }
        }

        private void LoadWordlistFromResource()
        {
            try
            {
                using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Lockr.Wordlist.txt"))
                {
                    if (stream != null)
                    {
                        using (StreamReader reader = new StreamReader(stream))
                        {
                            string content = reader.ReadToEnd();
                            wordList = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                       .Select(line => Regex.Match(line, @"^\d+\s+(.+)$"))
                                       .Where(match => match.Success)
                                       .Select(match => match.Groups[1].Value.Trim())
                                       .ToList();
                        }

                        if (wordList.Count > 0)
                        {
                            StatusText.Text = $"Wordlist loaded from embedded resource ({wordList.Count} words). Ready.";
                        }
                        else
                        {
                            StatusText.Text = "Embedded wordlist is empty or incorrectly formatted.";
                            MessageBox.Show("The embedded wordlist appears to be invalid.", "Resource Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            GeneratePassphraseButton.IsEnabled = false;
                            PassphraseWordCountSlider.IsEnabled = false;
                            PassphraseSeparator.IsEnabled = false;
                        }
                    }
                    else
                    {
                        StatusText.Text = "Embedded wordlist resource not found.";
                        MessageBox.Show("The embedded wordlist resource could not be found.", "Resource Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        GeneratePassphraseButton.IsEnabled = false;
                        PassphraseWordCountSlider.IsEnabled = false;
                        PassphraseSeparator.IsEnabled = false;
                    }
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error reading embedded wordlist.";
                MessageBox.Show($"Error reading embedded wordlist: {ex.Message}", "Resource Error", MessageBoxButton.OK, MessageBoxImage.Error);
                GeneratePassphraseButton.IsEnabled = false;
                PassphraseWordCountSlider.IsEnabled = false;
                PassphraseSeparator.IsEnabled = false;
            }
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                this.DragMove();
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void MaximizeRestoreButton_Click(object sender, RoutedEventArgs e)
        {
            if (this.WindowState == WindowState.Maximized)
            {
                this.WindowState = WindowState.Normal;
            }
            else
            {
                this.WindowState = WindowState.Maximized;
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void GeneratePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                int length = (int)PasswordLengthSlider.Value;
                bool useLower = IncludeLowercase.IsChecked == true;
                bool useUpper = IncludeUppercase.IsChecked == true;
                bool useNumbers = IncludeNumbers.IsChecked == true;
                bool useSymbols = IncludeSymbols.IsChecked == true;

                GeneratedPasswordOutput.Text = GenerateRandomPassword(length, useLower, useUpper, useNumbers, useSymbols);
                UpdatePasswordStrengthIndicator();
                StatusText.Text = "Password generated successfully.";
            }
            catch (ArgumentException argEx)
            {
                StatusText.Text = $"Error: {argEx.Message}";
                MessageBox.Show(argEx.Message, "Generation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                GeneratedPasswordOutput.Text = string.Empty;
                UpdatePasswordStrengthIndicator();
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error generating password.";
                MessageBox.Show($"An unexpected error occurred: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                GeneratedPasswordOutput.Text = string.Empty;
                UpdatePasswordStrengthIndicator();
            }
        }

        private void GeneratePassphraseButton_Click(object sender, RoutedEventArgs e)
        {
            if (wordList == null || wordList.Count == 0)
            {
                StatusText.Text = "Wordlist not loaded or empty.";
                MessageBox.Show("Cannot generate passphrase because the wordlist is missing or empty.", "Wordlist Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            try
            {
                int wordCount = (int)PassphraseWordCountSlider.Value;
                string separator = PassphraseSeparator.Text;
                if (string.IsNullOrEmpty(separator))
                {
                    separator = "-";
                    PassphraseSeparator.Text = separator;
                }

                string generatedPassphrase = GenerateRandomPassphrase(wordCount, separator);
                GeneratedPassphraseOutput.Text = generatedPassphrase;
                StatusText.Text = "Passphrase generated successfully.";

                // NEW: Call the update method for passphrase strength and entropy
                UpdatePassphraseStrengthIndicator(generatedPassphrase);

            }
            catch (Exception ex)
            {
                StatusText.Text = "Error generating passphrase.";
                MessageBox.Show($"An unexpected error occurred: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                GeneratedPassphraseOutput.Text = string.Empty;
                // Reset indicator on error
                UpdatePassphraseStrengthIndicator(string.Empty);
            }
        }

        //new-kdf
        private void DeriveKeyButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string password = KdfPasswordInput.Text;
                string salt = KdfSaltInput.Text;
                int keyLength;

                if (string.IsNullOrEmpty(password))
                {
                    StatusText.Text = "Error: Password cannot be empty.";
                    MessageBox.Show("Please enter a password or passphrase.", "Input Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    KdfOutput.Text = string.Empty;
                    return;
                }

                if (!int.TryParse(KdfKeyLength.Text, out keyLength) || keyLength <= 0)
                {
                    StatusText.Text = "Error: Invalid key length.";
                    MessageBox.Show("Please enter a valid positive integer for key length.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    KdfOutput.Text = string.Empty;
                    return;
                }

                byte[] saltBytes;
                if (string.IsNullOrEmpty(salt))
                {
                    // Generate a random salt if none is provided
                    saltBytes = GenerateRandomBytes(16);
                    KdfSaltInput.Text = Convert.ToBase64String(saltBytes); // Display generated salt
                }
                else
                {
                    saltBytes = Encoding.UTF8.GetBytes(salt);
                }

                byte[] derivedKey = null;

                if (Pbkdf2Radio.IsChecked == true)
                {
                    int iterations;
                    if (!int.TryParse(Pbkdf2Iterations.Text, out iterations) || iterations <= 0)
                    {
                        StatusText.Text = "Error: Invalid PBKDF2 iterations.";
                        MessageBox.Show("Please enter a valid positive integer for PBKDF2 iterations.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        KdfOutput.Text = string.Empty;
                        return;
                    }
                    derivedKey = DeriveKeyPbkdf2(password, saltBytes, iterations, keyLength);
                    StatusText.Text = "PBKDF2 key derived successfully.";
                }
                else if (Argon2Radio.IsChecked == true)
                {
                    int memory = 32;    // Default value of 32 MB if parsing fails
                    int time = 4;       // Default value of 4 iterations if parsing fails
                    int parallelism = 1; // Default value of 1 thread if parsing fails

                    // Safely parse memory parameter
                    if (!int.TryParse(Argon2Memory.Text, out memory) || memory <= 0)
                    {
                        StatusText.Text = "Warning: Using default memory value (32 MB).";
                        memory = 32; // Default to 32 MB
                    }

                    // Safely parse time parameter
                    if (!int.TryParse(Argon2Time.Text, out time) || time <= 0)
                    {
                        StatusText.Text = "Warning: Using default time value (4 iterations).";
                        time = 4; // Default to 4 iterations
                    }

                    // Safely parse parallelism parameter
                    if (!int.TryParse(Argon2Parallelism.Text, out parallelism) || parallelism <= 0)
                    {
                        StatusText.Text = "Warning: Using default parallelism value (1 thread).";
                        parallelism = 1; // Default to 1 thread
                    }

                    try
                    {
                        derivedKey = DeriveKeyArgon2(password, saltBytes, memory, time, parallelism, keyLength);
                        StatusText.Text = "Argon2 key derived successfully.";
                    }
                    catch (Exception ex)
                    {
                        StatusText.Text = "Error deriving Argon2 key.";
                        MessageBox.Show($"Argon2 error: {ex.Message}\n\nTry lower memory values (8-64 MB) and ensure all parameters are valid.",
                            "Argon2 Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        KdfOutput.Text = string.Empty;
                        return;
                    }
                }
                else
                {
                    StatusText.Text = "Error: KDF algorithm not selected.";
                    MessageBox.Show("Please select a KDF algorithm.", "Selection Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    KdfOutput.Text = string.Empty;
                    return;
                }

                KdfOutput.Text = Convert.ToBase64String(derivedKey);
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error deriving key.";
                MessageBox.Show($"An unexpected error occurred: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                KdfOutput.Text = string.Empty;
            }
        }

        private void CopyKdfOutputButton_Click(object sender, RoutedEventArgs e)
        {
            CopyTextToClipboard(KdfOutput.Text, "Derived Key");
        }
        //new

        private byte[] DeriveKeyArgon2(string password, byte[] salt, int memory, int time, int parallelism, int keyLength)
        {
            try
            {
                // Validate inputs with reasonable constraints
                if (memory <= 0)
                    memory = 8; // Default to 8MB if invalid
                else if (memory > 64)
                    memory = 64; // Cap at 64MB as per error message suggestion

                if (time <= 0)
                    time = 2; // Default to 2 iterations if invalid
                else if (time > 10)
                    time = 10; // Cap at reasonable maximum

                if (parallelism <= 0)
                    parallelism = 1; // Default to 1 thread if invalid
                else if (parallelism > Environment.ProcessorCount)
                    parallelism = Environment.ProcessorCount; // Cap at available processors

                // Create salt if null or empty
                if (salt == null || salt.Length == 0)
                    salt = GenerateRandomBytes(16);

                using (var argon2 = new Konscious.Security.Cryptography.Argon2id(Encoding.UTF8.GetBytes(password)))
                {
                    argon2.Salt = salt;
                    argon2.MemorySize = memory * 1024; // Convert MB to KB
                    argon2.Iterations = time;
                    argon2.DegreeOfParallelism = parallelism;

                    return argon2.GetBytes(keyLength);
                }
            }
            catch (Exception ex)
            {
                // Log the specific error for debugging
                Console.WriteLine($"Argon2 error: {ex.Message}");
                // Re-throw to be caught by the calling code
                throw new Exception($"Argon2 key derivation failed: {ex.Message}", ex);
            }
        }

        private void KdfAlgorithm_Checked(object sender, RoutedEventArgs e)
        {
            Pbkdf2Params.Visibility = Pbkdf2Radio.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            Argon2Params.Visibility = Argon2Radio.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        }

        // /new


        private void HashPassphraseButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string passphrase = PassphraseToHashInput.Text;
                string salt = SaltInput.Text;

                if (string.IsNullOrEmpty(passphrase))
                {
                    StatusText.Text = "Please enter a passphrase to hash.";
                    MessageBox.Show("Passphrase cannot be empty.", "Input Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    HashedOutput.Text = string.Empty;
                    return;
                }

                string hashedBase64 = HashStringSHA256(passphrase, salt);

                if (int.TryParse(OutputLengthControl.Text, out int desiredLength) && desiredLength > 0)
                {
                    if (hashedBase64.Length > desiredLength)
                    {
                        HashedOutput.Text = hashedBase64.Substring(0, desiredLength);
                        StatusText.Text = "Passphrase hashed and trimmed.";
                    }
                    else
                    {
                        HashedOutput.Text = hashedBase64;
                        StatusText.Text = "Passphrase hashed successfully.";
                    }
                }
                else
                {
                    HashedOutput.Text = hashedBase64;
                    StatusText.Text = "Passphrase hashed successfully.";
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error hashing passphrase.";
                MessageBox.Show($"An unexpected error occurred: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                HashedOutput.Text = string.Empty;
            }
        }

        private void CopyPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            CopyTextToClipboard(GeneratedPasswordOutput.Text, "Password");
        }

        private void CopyPassphraseButton_Click(object sender, RoutedEventArgs e)
        {
            CopyTextToClipboard(GeneratedPassphraseOutput.Text, "Passphrase");
        }

        private void CopyHashButton_Click(object sender, RoutedEventArgs e)
        {
            CopyTextToClipboard(HashedOutput.Text, "Hash");
        }

        private void LoadCustomWordlistButton_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog
            {
                DefaultExt = ".txt",
                Filter = "Text documents (.txt)|*.txt",
                Title = "Select Wordlist File"
            };

            bool? result = dlg.ShowDialog();

            if (result == true)
            {
                try
                {
                    string filePath = dlg.FileName;
                    LoadWordlistFromFile(filePath);


                    if (!GeneratePassphraseButton.IsEnabled)
                    {
                        GeneratePassphraseButton.IsEnabled = true;
                        PassphraseWordCountSlider.IsEnabled = true;
                        PassphraseSeparator.IsEnabled = true;
                    }
                }
                catch (Exception ex)
                {
                    StatusText.Text = "Failed to load custom wordlist.";
                    MessageBox.Show($"An error occurred loading the custom wordlist: {ex.Message}",
                        "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void CopyTextToClipboard(string text, string type)
        {
            if (!string.IsNullOrEmpty(text))
            {
                try
                {
                    Clipboard.SetText(text);
                    StatusText.Text = $"{type} copied to clipboard!";
                }
                catch (Exception ex)
                {
                    StatusText.Text = $"Failed to copy {type.ToLower()} to clipboard.";
                    MessageBox.Show($"Could not copy to clipboard: {ex.Message}", "Clipboard Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            else
            {
                StatusText.Text = $"No {type.ToLower()} to copy.";
            }
        }

        private string GenerateRandomPassword(int length, bool includeLower, bool includeUpper, bool includeNumbers, bool includeSymbols)
        {
            const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
            const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string NumberChars = "0123456789";
            const string SymbolChars = "!@#$%^&*()-_=+[]{}|;:,.<>/?";

            StringBuilder charPool = new StringBuilder();
            if (includeLower) charPool.Append(LowercaseChars);
            if (includeUpper) charPool.Append(UppercaseChars);
            if (includeNumbers) charPool.Append(NumberChars);
            if (includeSymbols) charPool.Append(SymbolChars);

            if (charPool.Length == 0)
            {
                throw new ArgumentException("At least one character set must be selected.");
            }

            StringBuilder password = new StringBuilder(length);
            byte[] randomBytes = new byte[length];

            rng.GetBytes(randomBytes);

            for (int i = 0; i < length; i++)
            {
                int charIndex = randomBytes[i] % charPool.Length;
                password.Append(charPool[charIndex]);
            }

            return password.ToString();


        }

        private string GenerateRandomPassphrase(int wordCount, string separator)
        {
            if (wordList == null || wordList.Count == 0)
            {
                throw new InvalidOperationException("Wordlist is not loaded or is empty.");
            }
            if (wordCount <= 0)
            {
                return string.Empty;
            }

            List<string> phraseParts = new List<string>();
            byte[] randomNumberBytes = new byte[4];
            bool includeSymbols = IncludeSymbolsPassphrase.IsChecked ?? false;
            bool extraSpicy = ExtraSpicyPassphrase.IsChecked ?? false;

            for (int i = 0; i < wordCount; i++)
            {
                rng.GetBytes(randomNumberBytes);
                int wordIndex = Math.Abs(BitConverter.ToInt32(randomNumberBytes, 0)) % wordList.Count;
                string word = wordList[wordIndex];

                // Apply "Extra Spicy" capitalization if enabled
                if (extraSpicy)
                {
                    StringBuilder spicyWord = new StringBuilder(word.Length);
                    for (int j = 0; j < word.Length; j++)
                    {
                        rng.GetBytes(randomNumberBytes);
                        double randomValue = (double)Math.Abs(BitConverter.ToInt32(randomNumberBytes, 0)) / int.MaxValue;

                        if (randomValue < CapitalizationPercentage)
                        {
                            spicyWord.Append(char.ToUpper(word[j]));
                        }
                        else
                        {
                            spicyWord.Append(word[j]);
                        }
                    }
                    word = spicyWord.ToString();
                }

                // Generate the random number suffix
                rng.GetBytes(randomNumberBytes);
                int numberSuffix = Math.Abs(BitConverter.ToInt32(randomNumberBytes, 0)) % 100;

                // Add random symbol if enabled
                string symbolSuffix = "";
                if (includeSymbols)
                {
                    rng.GetBytes(randomNumberBytes);
                    int symbolIndex = Math.Abs(BitConverter.ToInt32(randomNumberBytes, 0)) % SymbolCharsPassphrase.Length;
                    symbolSuffix = SymbolCharsPassphrase[symbolIndex].ToString();
                }

                phraseParts.Add($"{word}{numberSuffix}{symbolSuffix}");
            }

            return string.Join(separator, phraseParts);
        }

        private string HashStringSHA256(string input, string salt = "")
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input + salt);
                byte[] hashBytes = sha256Hash.ComputeHash(inputBytes);

                string base64 = Convert.ToBase64String(hashBytes)
                                      .Replace('+', '-')
                                      .Replace('/', '_')
                                      .TrimEnd('=');
                return base64;
            }
        }

        private void UpdatePasswordStrengthIndicator()
        {
            string password = GeneratedPasswordOutput.Text;
            int score = CalculatePasswordStrength(password);
            PasswordStrengthBar.Value = score;

            if (score < 35)
            {
                PasswordStrengthLabel.Text = "Very Weak";
                PasswordStrengthBar.Foreground = System.Windows.Media.Brushes.Red;
            }
            else if (score < 50)
            {
                PasswordStrengthLabel.Text = "Weak";
                PasswordStrengthBar.Foreground = System.Windows.Media.Brushes.OrangeRed;
            }
            else if (score < 75)
            {
                PasswordStrengthLabel.Text = "Medium";
                PasswordStrengthBar.Foreground = System.Windows.Media.Brushes.Orange;
            }
            else if (score < 90)
            {
                PasswordStrengthLabel.Text = "Strong";
                PasswordStrengthBar.Foreground = System.Windows.Media.Brushes.YellowGreen;
            }
            else
            {
                PasswordStrengthLabel.Text = "Very Strong";
                PasswordStrengthBar.Foreground = System.Windows.Media.Brushes.LimeGreen;
            }


            if (!string.IsNullOrEmpty(password))
            {
                var result = Zxcvbn.Core.EvaluatePassword(password);
                double entropy = result.GuessesLog10 * Math.Log2(10);
                PasswordEntropyLabel.Text = $"Entropy: {entropy:F2} bits";
            }
            else
            {
                PasswordEntropyLabel.Text = "Entropy: 0.00 bits";
            }
        }

        private void UpdatePassphraseStrengthIndicator(string passphrase)
        {
            int score = CalculatePasswordStrength(passphrase);
            PassphraseStrengthBar.Value = score;

            if (score < 35)
            {
                PassphraseStrengthLabel.Text = "Very Weak";
                PassphraseStrengthBar.Foreground = System.Windows.Media.Brushes.Red;
            }
            else if (score < 50)
            {
                PassphraseStrengthLabel.Text = "Weak";
                PassphraseStrengthBar.Foreground = System.Windows.Media.Brushes.OrangeRed;
            }
            else if (score < 75)
            {
                PassphraseStrengthLabel.Text = "Medium";
                PassphraseStrengthBar.Foreground = System.Windows.Media.Brushes.Orange;
            }
            else if (score < 90)
            {
                PassphraseStrengthLabel.Text = "Strong";
                PassphraseStrengthBar.Foreground = System.Windows.Media.Brushes.YellowGreen;
            }
            else
            {
                PassphraseStrengthLabel.Text = "Very Strong";
                PassphraseStrengthBar.Foreground = System.Windows.Media.Brushes.LimeGreen;
            }

            // Update entropy label (already exists, but ensuring context)
            if (!string.IsNullOrEmpty(passphrase))
            {
                var result = Zxcvbn.Core.EvaluatePassword(passphrase);
                double entropy = result.GuessesLog10 * Math.Log2(10);
                PassphraseEntropyLabel.Text = $"Entropy: {entropy:F2} bits";
            }
            else
            {
                PassphraseEntropyLabel.Text = "Entropy: 0.00 bits";
            }
        }

        private int CalculatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return 0;

            var result = Zxcvbn.Core.EvaluatePassword(password);

            int score = 0;
            switch (result.Score)
            {
                case 0:
                    score = 15; // Very Weak
                    break;
                case 1:
                    score = 40; // Weak
                    break;
                case 2:
                    score = 65; // Medium
                    break;
                case 3:
                    score = 80; // Strong
                    break;
                case 4:
                    score = 100; // Very Strong
                    break;
            }

            return Math.Max(0, Math.Min(score, 100));
        }

        private bool HasRepeatingChars(string input, int sequenceLength)
        {
            for (int i = 0; i <= input.Length - sequenceLength; i++)
            {
                char firstChar = input[i];
                bool sequenceFound = true;
                for (int j = 1; j < sequenceLength; j++)
                {
                    if (input[i + j] != firstChar)
                    {
                        sequenceFound = false;
                        break;
                    }
                }
                if (sequenceFound) return true;
            }
            return false;
        }

        private bool HasSequentialChars(string input, int sequenceLength)
        {
            if (input.Length < sequenceLength) return false;
            for (int i = 0; i <= input.Length - sequenceLength; i++)
            {
                bool sequenceFound = true;
                for (int j = 0; j < sequenceLength - 1; j++)
                {
                    if (input[i + j + 1] != input[i + j] + 1)
                    {
                        sequenceFound = false;
                        break;
                    }
                }
                if (sequenceFound) return true;
            }
            return false;
        }

        protected override void OnClosed(EventArgs e)
        {
            GeneratedPasswordOutput.Clear();
            GeneratedPassphraseOutput.Clear();
            HashedOutput.Clear();
            PassphraseToHashInput.Clear();
            SaltInput.Clear();

            wordList = null;

            base.OnClosed(e);
        }

        private void ProcessEncryptionButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string password = EncryptionKey.Password;
                string salt = EncryptionSalt.Text;
                string input = EncryptionInput.Text;

                if (string.IsNullOrEmpty(password))
                {
                    StatusText.Text = "Error: Encryption key cannot be empty";
                    MessageBox.Show("Please enter an encryption key.", "Input Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(input))
                {
                    StatusText.Text = "Error: Input text cannot be empty";
                    MessageBox.Show("Please enter text to process.", "Input Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                byte[] inputBytes;
                try
                {
                    if (InputText.IsChecked == true)
                    {
                        inputBytes = Encoding.UTF8.GetBytes(input);
                    }
                    else if (InputBase64.IsChecked == true)
                    {
                        inputBytes = Convert.FromBase64String(input);
                    }
                    else if (InputHex.IsChecked == true)
                    {
                        inputBytes = HexStringToByteArray(input);
                    }
                    else
                    {
                        throw new InvalidOperationException("Input format not selected");
                    }
                }
                catch (Exception ex)
                {
                    StatusText.Text = "Error: Could not parse input with selected format";
                    MessageBox.Show($"Failed to parse input: {ex.Message}", "Format Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Process the encryption/decryption
                byte[] resultBytes;
                if (EncryptRadio.IsChecked == true)
                {
                    resultBytes = AesGcmEncrypt(inputBytes, password, salt);
                    StatusText.Text = "Encryption successful";
                }
                else if (DecryptRadio.IsChecked == true)
                {
                    try
                    {
                        resultBytes = AesGcmDecrypt(inputBytes, password, salt);
                        StatusText.Text = "Decryption successful";
                    }
                    catch (CryptographicException cryptEx)
                    {
                        StatusText.Text = "Decryption failed: Authentication tag mismatch";
                        MessageBox.Show("Decryption failed. This could be due to an incorrect key, salt, or corrupted data.",
                            "Decryption Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }
                }
                else
                {
                    throw new InvalidOperationException("Operation not selected");
                }

                // Format output according to selection
                string result;
                if (OutputText.IsChecked == true)
                {
                    try
                    {
                        result = Encoding.UTF8.GetString(resultBytes);
                    }
                    catch
                    {
                        StatusText.Text = "Warning: Result contains non-text data. Switching to Base64 output.";
                        OutputText.IsChecked = false;
                        OutputBase64.IsChecked = true;
                        result = Convert.ToBase64String(resultBytes);
                    }
                }
                else if (OutputBase64.IsChecked == true)
                {
                    result = Convert.ToBase64String(resultBytes);
                }
                else if (OutputHex.IsChecked == true)
                {
                    result = BitConverter.ToString(resultBytes).Replace("-", "").ToLower();
                }
                else
                {
                    throw new InvalidOperationException("Output format not selected");
                }

                EncryptionOutput.Text = result;
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error processing encryption/decryption";
                MessageBox.Show($"An error occurred: {ex.Message}", "Processing Error", MessageBoxButton.OK, MessageBoxImage.Error);
                EncryptionOutput.Text = string.Empty;
            }
        }

        private void CopyEncryptionOutputButton_Click(object sender, RoutedEventArgs e)
        {
            CopyTextToClipboard(EncryptionOutput.Text, "Encryption output");
        }
        private byte[] AesGcmEncrypt(byte[] plaintext, string password, string salt)
        {
            // Generate a key from the password and salt using PBKDF2
            byte[] saltBytes = !string.IsNullOrEmpty(salt) ? Encoding.UTF8.GetBytes(salt) : GenerateRandomBytes(16);
            byte[] key = GenerateKeyFromPassword(password, saltBytes, 32); // 32 bytes for AES-256

            // Generate a random nonce/IV
            byte[] nonce = GenerateRandomBytes(12);

            // Prepare output array (format: salt_length(1) + salt + nonce_length(1) + nonce + ciphertext + tag(16))
            byte[] output = new byte[1 + saltBytes.Length + 1 + nonce.Length + plaintext.Length + 16];
            int position = 0;

            // Add salt length and salt
            output[position++] = (byte)saltBytes.Length;
            Buffer.BlockCopy(saltBytes, 0, output, position, saltBytes.Length);
            position += saltBytes.Length;

            // Add nonce length and nonce
            output[position++] = (byte)nonce.Length;
            Buffer.BlockCopy(nonce, 0, output, position, nonce.Length);
            position += nonce.Length;

            // Encrypt using AES-GCM
            using (AesGcm aesGcm = new AesGcm(key, 128))
            {
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[16]; // AES-GCM uses a 16-byte authentication tag

                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

                Buffer.BlockCopy(ciphertext, 0, output, position, ciphertext.Length);
                position += ciphertext.Length;

                Buffer.BlockCopy(tag, 0, output, position, tag.Length);
            }

            return output;
        }

        // AES-256 GCM Decryption
        private byte[] AesGcmDecrypt(byte[] ciphertextWithMetadata, string password, string salt)
        {
            // Extract salt, nonce from the input
            int position = 0;

            // Extract salt
            int saltLength = ciphertextWithMetadata[position++];
            byte[] saltBytes;

            if (!string.IsNullOrEmpty(salt))
            {
                // Use provided salt instead of embedded one
                saltBytes = Encoding.UTF8.GetBytes(salt);
                // Skip the embedded salt in the ciphertext
                position += saltLength;
            }
            else
            {
                // Use the embedded salt
                saltBytes = new byte[saltLength];
                Buffer.BlockCopy(ciphertextWithMetadata, position, saltBytes, 0, saltLength);
                position += saltLength;
            }

            // Generate the key using PBKDF2
            byte[] key = GenerateKeyFromPassword(password, saltBytes, 32); // 32 bytes for AES-256

            // Extract nonce
            int nonceLength = ciphertextWithMetadata[position++];
            byte[] nonce = new byte[nonceLength];
            Buffer.BlockCopy(ciphertextWithMetadata, position, nonce, 0, nonceLength);
            position += nonceLength;

            // The rest is ciphertext and tag
            int ciphertextLength = ciphertextWithMetadata.Length - position - 16; // Last 16 bytes are the tag
            byte[] ciphertext = new byte[ciphertextLength];
            byte[] tag = new byte[16];

            Buffer.BlockCopy(ciphertextWithMetadata, position, ciphertext, 0, ciphertextLength);
            position += ciphertextLength;

            Buffer.BlockCopy(ciphertextWithMetadata, position, tag, 0, 16);

            // Decrypt
            byte[] plaintext = new byte[ciphertextLength];
            using (AesGcm aesGcm = new AesGcm(key, 128))
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            return plaintext;
        }

        // Utility methods for encryption
        private byte[] GenerateRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return bytes;
        }

        private byte[] GenerateKeyFromPassword(string password, byte[] salt, int keyLength)
        {
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
            {
                return deriveBytes.GetBytes(keyLength);
            }
        }

        private byte[] HexStringToByteArray(string hex)
        {
            // Remove any non-hex characters (like spaces or dashes)
            hex = new string(hex.Where(c =>
                (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F')).ToArray());

            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("Hex string must have an even number of digits");
            }

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }

    }
}
