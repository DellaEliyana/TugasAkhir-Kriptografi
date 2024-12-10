
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# 1. Membuat pasangan kunci RSA
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print("Kunci RSA berhasil dibuat:")
    print("Kunci Privat disimpan sebagai 'private_key.pem'")
    print("Kunci Publik disimpan sebagai 'public_key.pem'")

# 2. Membuat tanda tangan digital
def sign_document(document_path):
    with open("private_key.pem", "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    
    with open(document_path, "rb") as doc:
        document_data = doc.read()
    
    # Hash dokumen
    hash_obj = SHA256.new(document_data)
    # Tanda tangani hash
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    
    # Simpan tanda tangan
    with open("signature.sig", "wb") as sig_file:
        sig_file.write(signature)
    
    print("Tanda tangan digital berhasil dibuat dan disimpan di 'signature.sig'.")

# 3. Verifikasi tanda tangan digital
def verify_signature(document_path):
    with open("public_key.pem", "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    
    with open(document_path, "rb") as doc:
        document_data = doc.read()
    
    with open("signature.sig", "rb") as sig_file:
        signature = sig_file.read()
    
    # Hash dokumen
    hash_obj = SHA256.new(document_data)

    try:
        # Verifikasi tanda tangan
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        print("Tanda tangan digital valid!")
    except (ValueError, TypeError):
        print("Tanda tangan digital tidak valid!")

# Pilihan eksekusi
if __name__ == "__main__":
    # Ganti nama file dengan dokumen yang ingin Anda gunakan
    document_path = r"C:\Users\ASUS ROG\Downloads\Python\Zidan.pdf"

    print("=== Pilihan ===")
    print("1. Buat pasangan kunci")
    print("2. Tanda tangani dokumen")
    print("3. Verifikasi tanda tangan")
    choice = input("Masukkan pilihan Anda (1/2/3): ")

    if choice == "1":
        generate_keys()
    elif choice == "2":
        sign_document(document_path)
    elif choice == "3":
        verify_signature(document_path)
    else:
        print("Pilihan tidak valid!")
()