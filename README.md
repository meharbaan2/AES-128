# AES-128 Encryption Implementation 🔐

This project implements the **AES (Advanced Encryption Standard)** algorithm in C, focusing on **128-bit key and 128-bit block size**.  
It demonstrates the encryption process, key expansion, and round-by-round transformations over 10 rounds.  

Additionally, a **custom AES variant** with a modified S-box (row swaps) is included to explore the effect of structural changes on encryption.

---

## ✨ Features
- **Original AES-128 encryption** with round-by-round output.  
- **Custom S-box variant** for experimentation and analysis.  
- **Key expansion** for standard and modified AES.  
- Easy to modify **plaintext** and **key** for testing.  

---

## 🛠️ Code Structure
- `main()` – Entry point; sets up S-box, plaintext, key, performs encryption.  
- `print_metadata()` – Prints project information.  
- `init_modified_s_box(A, B)` – Creates modified S-box by swapping rows A and B.  
- `key_expansion()` / `modified_key_expansion()` – Generates round keys.  
- `aes_encrypt()` – Performs AES encryption on a 4x4 state.  
- `memcpy_to_state()` – Converts linear array into AES state matrix.  

---

## 🚀 Usage
- Program displays **round-by-round encryption output** for both Original AES and Modified AES.  
- Modify plaintext and key in `main()` to test different inputs.  
- Compare standard AES output with the modified S-box variant to study **structural sensitivity**.

---

## ⚠️ Notes
- **ECB mode** is used for demonstration; it is not secure for multiple-block data.  
- This project is primarily **educational**, suitable for understanding AES internals and classical cryptanalysis.  
- Future extensions could include:
  - Other modes (CBC, CFB, OFB, CTR)  
  - AES decryption  
  - Performance evaluation  
