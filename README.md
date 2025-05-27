# Raw-Socket SYN Tarayıcı & OS Parmak İzi

Basit bir Python3 aracı; ham soketler kullanarak hedefin portlarını TCP SYN taramasıyla kontrol eder ve TTL ile pencere boyutuna dayalı temel işletim sistemi tahmini yapar.

---

## Özellikler

- **Port Aralığı Tarama**: Tek port, virgülle ayrılmış liste veya aralık (örn. `1-1024`, `22,80,443`).
- **SYN-Only Tarama**: Ham IP+TCP SYN paketleri oluşturur (tam TCP el sıkışması yapmaz).
- **Temel OS Parmak İzi**: TTL & TCP pencere boyutuna bakarak "Windows-benzeri", "Linux/Unix-benzeri" vb. tahminler yapar.
- **Servis Adı Çözümleme**: Açık portları bilinen TCP servis adlarına dönüştürmeye çalışır.
- **Özelleştirilebilir Zaman Aşımı**: Her port için yanıt süresi sınırı belirlenebilir.

---

## Gereksinimler

- **Python 3.6+**
- **Linux** veya **macOS** (ham soket desteği gerekir; Windows genellikle izin vermez)
- **Root / Yönetici** yetkileri (ham soket oluşturmak için)

---

## Kurulum

1. Repoyu klonlayın veya indirin:
   ```bash
   git clone https://github.com/xarsdegil/Open-Port-Scanner-With-Raw-Sockets.git
   cd raw-syn-scanner
   ```

2. (İsteğe bağlı) sanal ortam oluşturun:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Gerekli Python paketleri yok (yalnızca standart kütüphane kullanılır).

---

## Kullanım

```bash
sudo python3 scanner.py <hedef> [--ports PORTLAR] [--timeout SANIYE]
```

- `<hedef>`
  Taramak istediğiniz IP adresi veya etki alanı.

- `--ports PORTLAR` (varsayılan: `1-1024`)
  Tarama yapılacak portlar.
  - Aralık: `1-1024`
  - Liste: `22,80,443,8080`
  - Tek port: `443`

- `--timeout SANIYE` (varsayılan: `1.0`)
  Her port için bekleme süresi (saniye).

### Örnekler

1. **1–100 arası hızlı tarama**
   ```bash
   sudo python3 scanner.py 192.168.1.10 --ports 1-100
   ```

2. **Yaygın web portlarını kontrol etme**
   ```bash
   sudo python3 scanner.py example.com --ports 80,443,8080
   ```

3. **Yavaş yanıt veren hedef için uzun zaman aşımı**
   ```bash
   sudo python3 scanner.py 10.0.0.5 --ports 1-1024 --timeout 2.5
   ```

---

## Çalışma Prensibi

1. **IP Başlığı**
   - Minimal bir IPv4 başlığı (20 bayt) oluşturur ve checksum hesaplar.
2. **TCP SYN Segmenti**
   - SYN bayrağı set edilmiş TCP segmenti yaratır, sahte başlık (pseudo-header) ile checksum hesaplar.
3. **Gönderme & Alma**
   - Ham soketle SYN paketini yollar, ayrı bir ham TCP soketiyle SYN-ACK yanıtlarını dinler.
4. **Parmak İzi**
   - SYN-ACK alınca paketin TTL ve pencere boyutunu yakalar.
   - Tipik varsayılan değerleri kullanarak OS ailesi ve sürüm tahmini yapar.
5. **Servis Adı**
   - `socket.getservbyport()` ile portu bilinen servis adına dönüştürmeye çalışır.

---

## Notlar & Sınırlamalar

- **Durumsuz**: TCP el sıkışmasını tamamlamayan port resmi olarak "açık" kabul edilmez.
- **Root Gerektirir**: Yalnızca yönetici izinleriyle çalışır.
- **Tahmin Doğruluğu**: Yalnızca basit bir kestirim; gerçek araçlar daha fazla parametre kullanır.
- **Platform Desteği**: Linux üzerinde test edilmiştir.

---
