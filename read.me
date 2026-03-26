# 🛡️ Güvenli Web Yazılımı Geliştirme Vize Projesi Yol Haritası

**Öğrenci:** Safa Hacıbayramoğlu  
**Bölüm:** Bilişim Güvenliği Teknolojisi  
**Seçilen Senaryo:** Senaryo 4 - Veri Tabanı Tuzakları (SQLi Sandbox)  
**Rol:** Güvenlik Uzmanı / Sistem Mimarı Bakış Açısı  

---

## 📌 Proje Kapsamı ve Hedefi
Bu proje, açık kaynaklı bir web uygulamasının yaşam döngüsünü (kurulumdan canlı ortama geçişe kadar) "Güvenlik Uzmanı" gözüyle analiz etmeyi hedefler. Temel odak noktası, SQL Injection (SQLi) zafiyetlerini tespit etmek, sistem mimarisini incelemek ve kod seviyesinde güvenli (Parameterized Query/ORM) çözümler üretmektir.

---

## 🚀 Analiz ve Uygulama Aşamaları

### 1. Adım: Kurulum ve `install.sh` Analizi (Reverse Engineering)
* **Görev:** Uygulamanın kurulum scripti (`install.sh`) satır satır incelenecektir.
* **Analiz Soruları:**
    * Script dış kaynaklardan dosya çekerken (curl/wget) hash/imza kontrolü yapıyor mu?
    * Kurulum sırasında veritabanı kullanıcılarına gereksiz yüksek yetkiler (root/superuser) veriliyor mu?
    * Script hangi sistem dizinlerine yazma izni istiyor?

### 2. Adım: İzolasyon ve İz Bırakmadan Temizlik (Forensics & Cleanup)
* **Görev:** Uygulamanın kurulduğu sistemde bıraktığı dijital izler takip edilecektir.
* **Analiz Soruları:**
    * Kurulum sonrası `netstat` ile kontrol edildiğinde beklenmedik portlar açıldı mı?
    * Uygulama silindiğinde log dosyaları, geçici dosyalar ve veritabanı artıkları temizleniyor mu?
* **Yöntem:** Testler izole bir Sanal Makine (VM) üzerinde gerçekleştirilecektir.

### 3. Adım: İş Akışları ve CI/CD Pipeline Analizi (`.github/workflows`)
* **Görev:** Repoda bulunan GitHub Actions veya benzeri CI/CD süreçleri denetlenecektir.
* **Analiz Soruları:**
    * Pipeline içinde otomatik SQLi tarama araçları (SAST/DAST) entegre edilmiş mi?
    * Webhook yapılandırmaları ve API anahtarları (Secrets) güvenli mi?

### 4. Adım: Docker Mimarisi ve Konteyner Güvenliği
* **Görev:** `Dockerfile` ve `docker-compose.yml` yapılandırması analiz edilecektir.
* **Analiz Soruları:**
    * Veritabanı servisi dış ağa (host) gereksiz yere açık mı?
    * Docker imajı "unprivileged user" (düşük yetkili kullanıcı) ile mi çalışıyor?

### 5. Adım: Kaynak Kod ve Akış Analizi (Threat Modeling) 🔍
* **Görev:** Uygulamanın giriş noktaları (entrypoint) ve SQL sorgu yapısı incelenecektir.
* **Analiz Soruları:**
    * Kullanıcıdan alınan inputlar veritabanı sorgusuna "String Concatenation" (metin birleştirme) ile mi sokuluyor?
    * Tehdit modeli: Bir saldırgan giriş formundan veritabanı dump'ını nasıl alabilir?
* **Uygulama:** Tespit edilen güvensiz sorgular, **Parameterized Query (ORM)** kullanılarak modernize edilecek ve sistem güvenli hale getirilecektir.

---

## 📊 Beklenen Çıktılar
1. Kurulum ve sistem mimarisi analiz raporu.
2. Tespit edilen SQLi zafiyetlerinin ekran görüntüleri ve PoC (Proof of Concept) çalışmaları.
3. Güvenli kod standartlarına göre güncellenmiş kaynak kod ve yama dosyası.
