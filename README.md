# RustPass

Rust ile geliştirilmiş, tamamen yerel, bağımsız ve güvenli masaüstü parola yöneticisi.

RustPass; verilerinizi üçüncü taraf bulut sunucularına göndermeden, yalnızca yerel diskinizde şifrelenmiş olarak saklayan taşınabilir (tek ikili dosya) bir parola yöneticisidir.

---

## 🔒 Güvenlik Özellikleri

- **AES-256-GCM Şifreleme**: Kasa içeriği ve hassas veriler kimlik doğrulamalı AES-256-GCM ile şifrelenir.
- **Argon2id Anahtar Türetme**: Ana parola, brute-force ve GPU/ASIC saldırılarına karşı OWASP standartlarına uygun Argon2id KDF ile işlenir.
- **Bellek Güvenliği (Zeroize)**: Şifreler ve anahtarlar kullanım sonrası RAM üzerinde `zeroize` ile tamamen silinir.
- **Tamamen Çevrimdışı**: İnternet bağlantısı gerektirmez, telemetri veya izleme içermez.
- **Statik SQLite Depolama**: Harici veritabanı sürücüsü gerektirmeyen gömülü SQLite altyapısı.

---

## 🚀 Temel Yetenekler

- 📋 Hesap adı, kullanıcı adı, parola, kategori, URL ve özel not saklama
- 🎲 Özelleştirilebilir güvenli parola üretici
- 🔍 Gerçek zamanlı arama ve filtreleme
- ⏱️ Otomatik pano temizleme / güvenli kopyalama
- 💾 Şifreli kasa yedekleme ve dışa/içe aktarma
- ⚡ Hızlı ve hafif `egui` tabanlı grafik arayüz

---

## 🛠️ Kurulum ve Derleme

### Gereksinimler

- [Rust ve Cargo](https://www.rust-lang.org/tools/install) (1.70+ önerilir)
- **Linux** kullanıcıları için temel pencere kütüphaneleri (gerekirse):
  ```bash
  # Debian / Ubuntu
  sudo apt-get install build-essential libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
  ```

### Derleme

Projeyi klonlayın ve release modunda derleyin:

```bash
git clone https://github.com/hackersuu/rustpass.git
cd rustpass
cargo build --release
```

Derlenen çalıştırılabilir dosya `target/release/rustpass` konumunda hazır olacaktır.

### Çalıştırma

```bash
cargo run --release
```

---

## 📜 Lisans

Bu proje **GNU General Public License v2.0 (GPLv2)** altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakabilirsiniz.
