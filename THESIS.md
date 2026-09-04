# YENİ NESİL WEB DİZİN VE VARLIK KEŞİF MOTORU: CAPSAICIN V2
## Kapsamlı Mimari ve Kod Analiz Tezi

---

### 1. ÖZET (ABSTRACT)
Bu çalışma, siber güvenlik profesyonelleri ve sızma testi uzmanları için geliştirilmiş, yüksek performanslı ve atlatma (evasion) odaklı bir web dizin ve varlık keşif motoru olan **Capsaicin v2** projesinin detaylı mimari ve algoritmik analizini sunmaktadır. Geleneksel keşif araçlarından (ffuf, gobuster vb.) farklı olarak Capsaicin, gelişmiş Web Uygulama Güvenlik Duvarlarını (WAF), Akamai, Cloudflare ve AWS Shield gibi koruma katmanlarını asimetrik tekniklerle atlatmayı (bypass) hedefler. Akıllı anomali tespiti, dinamik durum tabanlı fuzzing, TLS parmak izi sahtekarlığı (JA3/JA4 spoofing), entropi tabanlı hassas veri (secret) tespiti ve stokastik gecikme (jitter) gibi modüllere sahip olan aracın Go programlama dilindeki gerçeklemesi bu tezde derinlemesine incelenmiştir.

---

### 2. GİRİŞ
Modern web mimarilerinde güvenlik araştırmaları ve zafiyet tarama süreçleri, agresif WAF kuralları, oran sınırlandırma (rate limiting) ve TLS parmak izi doğrulama mekanizmaları nedeniyle giderek zorlaşmaktadır. Web sunucularında unutulan dizinlerin (directory), API endpoint'lerinin ve hassas yapılandırma dosyalarının tespiti için kullanılan araçlar artık sadece hızlı olmakla kalmamalı; aynı zamanda insan davranışı sergileyebilmeli, engelleme mekanizmalarını tanıyabilmeli ve sahte durum kodlarını (false-positives) dinamik olarak filtreleyebilmelidir. Capsaicin, bu ihtiyaçlara cevap verecek şekilde modüler, Concurrent (eş zamanlı) ve Context-Aware (bağlam farkında) bir yapıda inşa edilmiştir.

---

### 3. MİMARİ VE BİLEŞEN TASARIMI (ARCHITECTURE & COMPONENTS)

Capsaicin mimarisi 5 temel bileşen üzerine kurgulanmıştır:

#### 3.1. Çekirdek Tarama Motoru (`internal/scanner`)
Projenin beyni konumundaki `Engine` yapısı, Go'nun güçlü eşzamanlılık (concurrency) modelini kullanır. Bir `Worker Pool` yapısı kurularak `Task` (görev) kanalı üzerinden hedefler dağıtılır.
*   **Stateful Fuzzing & Method Fuzzing:** Her worker, hedef URL'ye istek atıp cevaplarını değerlendirir. Geleneksel tarayıcılar 405 (Method Not Allowed) yanıtını hata kabul ederken, Capsaicin `worker.go` içinde HTTP metodunu dinamik olarak (POST, PUT, DELETE, PATCH) değiştirerek hedefe tekrar saldırır.
*   **403/401 Bypass Motoru:** Erişim engeli alındığında, istek başlıklarına `X-Forwarded-For`, `X-Original-URL`, `Client-IP` gibi atlatma başlıklarını (Header Injection) otomatik olarak ekleyerek içerik filtrelemelerini (WAF) veya basit ters vektör korumalarını atlatmayı dener.

#### 3.2. Taşıma ve Atlatma Katmanı (`internal/transport`)
Bu modül, standart `net/http` kütüphanesinin kısıtlamalarından kurtularak son derece detaylı ağ manipülasyonları sunar.
*   **Jitter Motoru (`jitter.go`):** İstekler arasına Gauss (Gaussian) ve Pareto dağılımları kullanılarak stokastik (rastgele) gecikmeler eklenir. `paranoid` analiz modunda Pareto fonksiyonu sayesinde ara sıra "metin okuyan insan" benzeri uzun duraksamalar simüle edilerek yapay zeka tabanlı WAF davranışsal analizleri yanıltılır.
*   **TLS Spoofing & HTTP2 Force (`tls.go`, `h2.go`):** Sadece User-Agent değiştirmek günümüzde yeterli değildir. `utls` kütüphanesi kullanılarak istemcinin "ClientHello" paketindeki TLS parmak izi (JA3) gerçek bir Chrome, Safari veya Firefox tarayıcısı gibi gösterilir (Spoofing). `H2TransportBuilder` sınıfı ile asıl TCP soketi ele geçirilip HTTP/2 zorlanarak ağdaki SYN flood alarmlarının önüne geçmek hedeflenmiştir.
*   **Circuit Breaker (Devre Kesici):** Peş peşe gelen hedef çökmelerine (5xx Response) veya bağlantı kesintilerine karşı tarama motorunun kilitlenmesini engellemek için, sorunlu uç noktalardaki istekler geçici bir süreyle durdurulur (`CircuitBreaker` - `client.go`).

#### 3.3. Tespit ve Hata Ayıklama Modülü (`internal/detection`)
Bulguların doğruluğu, bu modüldeki yapılar üzerinden teyit edilir.
*   **Akıllı Kalibrasyon (Smart Calibration):** Orijinal hedefe rastgele tanımlı dizinlerle (Örn; `/capsaicin_cal_9871`) istek atılır. Dönen 403 veya 200 kodlu "sahte" (catch-all) sayfalar tespit edilir, sayfa yanıtının boyut (size), kelime sayısı (word count) ve satır sayısı (line count) bir referans (Baseline) olarak `CalibrationCache` belleğine (Map) alınır. Keşfedilen yeni dizinler referanslarla belli bir yüzde aralığında benzerlik gösterirse elenir.
*   **WAF İmza Tespiti (`waf.go`):** 16'dan fazla popüler Firewall sisteminin (Cloudflare, AWS WAF, Akamai vs.) header veya Response Body üzerindeki şablon imzaları kullanılarak WAF varlığı kesin olarak rapor edilir (`DetectWAF`).
*   **Sır ve Anahtar Tespiti (`secrets.go`):** Bulunan dosya içerikleri AWS Key, Stripe, Github Token ve Private Key gibi 15 farklı şablon ile test edilir (`Regexp`). Bu şablonlar dışında, karmaşık ve yüksek entropili Generic API metinleri yakalanır ve *Shannon Entropy* algoritması ile "Gerçek rastgele bir değer mi yoksa sadece metin mi" analizi yapılarak risk puanlamasına (Severity) tabi tutulur.

---

### 4. KOD SEVİYESİNDE ALGORİTMA İNCELEMESİ

Aşağıda temel algoritmaların Go tabanlı implementasyon kritikleri sunulmuştur.

#### 4.1. Entropi Analizi (Shannon Entropy)
Hassas veri aramalarında her regex eşleşmesi doğru değildir. (Örn: `password="benimsifrem"`). Capsaicin, potansiyel eşleşmeleri filtrelemek için bilgi teorisi yaklaşımını kullanır:
```go
// internal/detection/secrets.go
func ShannonEntropy(s string) float64 {
	// ... string karakter frekanslarının (freq) çıkarılması ...
	entropy := 0.0
	ft := float64(total)
	for _, count := range freq {
		if count == 0 { continue }
		p := float64(count) / ft
		entropy -= p * math.Log2(p) // - Σ p(x)*log2(p(x))
	}
	return entropy
}
```
*Bu fonksiyon ile bulunan potansiyel token 3.0 değerinden düşük bir entropiye sahipse tesadüf olarak kabul edilir ve raporlanmaz. Yüksek rastlantısallık, şifreleme ve key generatörlerin işaretidir.*

#### 4.2. TLS Parmak İzi Sahteciliği (Fingerprint Spoofing)
HTTP/2 zorunlu kılındığında uygulanan `DialTLS` override fonksiyonu:
```go
// internal/transport/h2.go (H2TransportBuilder.Build)
dialTLS := func(network, addr string, cfg *tls.Config) (net.Conn, error) {
    conn, err := b.Dialer.Dial(network, addr) // Ham TCP açılır
    // Bağlantı utls ile sarılır, b.HelloID (Örn. HelloChrome_120) enjekte edilir
    uConn := utls.UClient(conn, uCfg, b.HelloID)
    if err := uConn.Handshake(); err != nil {
        // WAF DROP Durumu
    }
    return uConn, nil
}
```
*Bu kodla Go Client'in varsayılan JA3 imzası ezilir. İletişim paketlerini inceleyen güvenlik analiz cihazları (IDS/IPS), trafiği sıradan bir Google Chrome veya iOS Safari internet tarayıcısı olarak kaydeder.*

#### 4.3. Bypass Stratejisi
`makeRequest` içinde status kod `403` olarak gelirse arka planda aşağıdaki bypass payload enjeksiyonu gerçekleştirilir:
```go
// internal/scanner/worker.go
bypassHeaders := map[string]string{
    "X-Forwarded-For":           "127.0.0.1",
    "X-Original-URL":            extractPath(url),
    "X-Rewrite-URL":             extractPath(url),
    "X-Custom-IP-Authorization": "127.0.0.1",
    "Client-IP":                 "127.0.0.1",
}
// Bu headerlar ile yeni istek atılır, eğer sonuç 200 veya 302 ise
// Sistem bunu Critical bir zafiyet olarak [BYPASS] etiketiyle işaretler.
```

---

### 5. PERFORMANS, RAPORLAMA VE CI/CD ENTEGRASYONU

*   **Raporlama Modülleri (`internal/reporting`):** Olası bulgular JSON veya interaktif HTML formatında dışarıya aktarılır. Yeni versiyon şeması (v3.1) ile her taramanın metaparametreleri saklanır.
*   **Fail-On CI Hattı:** Proje doğrudan test hatlarında (Pipeline) kullanılmak üzere tasarlanmıştır. `--fail-on` parametresi ile hedeflenen siber risk seviyesi (örn. "high" veya "critical") aşıldığında sistem Exit Code 2 döndürerek otomatik olarak DevOps sürecini keser.
*   **Deduplication (Veri Tekilleştirme):** Concurrent yapı nedeniyle aynı URL aynı metotla birden fazla kez işlenmesini önlemek için sync.Mutex kullanılarak `dedup.go` mekanizması devreye alınır, sadece en yüksek Severity skoruna sahip kayıt tutulur.

---

### 6. SONUÇ VE DEĞERLENDİRME

**Capsaicin v2**, standart bir `brute-force` aracı değildir. Web güvenliği yaklaşımını "sadece tara ve getir" mantalitesinden, "sistemi anla, kuralları dolan ve onaylanmış zafiyet sınıfını çıkar" mantalitesine taşımıştır.

*   *Öne Çıkan Güçlü Yönleri:*
    *   **utls** kütüphanesi sayesinde TLS JA3/JA4 spoofing yapabilmesi ve buna uyumlu HTTP başlıkları (`BrowserProfile`) atayabilmesi onu modern WAF'lara (Cloudflare JS/Captchası hariç, heuristik waf kurallarına) karşı çok tehlikeli yapar.
    *   **Jitter engine**, Pareto dağılımı matematiksel modelini kullanan ender sızma testi araçlarından biridir.
    *   **Shannon Entropy** ve **Secret Regex** ile kod içinde sızıntı avına çıkar.

*   *Geliştirilebilir veya Zayıf Yönleri:*
    *   Headless Browser gerektiren karmaşık JavaScript tabanlı korumalar (Cloudflare Turnstile, reCAPTCHA v3) için yerleşik bir çözüm barındırmamaktadır, bu tarz uç noktalarda HTTP istekleri direkt bloklanabilir.
    *   Fuzz modu `dynamic` olduğu senaryolarda Wordlist ile Memory (RAM) yönetimi aşırı şişme riski barındırır.

Bu proje, hem sızma testi (Red Team) uzmanları için güçlü bir taarruz gereci hem de savunmacı mühendisler (Blue Team/DevSecOps) için mükemmel bir kalite kontrol analizatörüdür.

*(Doğrudan `/home/toretto/capsaicin` projesi üzerinde yapılan analiz ve kaynak kod incelemelerine istinaden oluşturulmuştur.)*
