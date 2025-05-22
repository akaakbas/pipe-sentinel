# PipeSentinel

GitHub Actions workflow dosyalarının güvenlik analizi için geliştirilmiş bir araç.

## Özellikler

- Tehlikeli izinleri tespit etme
- Secret sızıntılarını tespit etme
- Üçüncü parti action'ları kontrol etme
- Tehlikeli komutları tespit etme
- Detaylı güvenlik raporları
- Adım adım çözüm önerileri
- CWE ve OWASP referansları
- Risk önceliklendirme

## Desteklenen Secret Türleri

- AWS Access Key
- Stripe API Key
- Twilio Auth Token
- SendGrid API Key
- DigitalOcean API Token
- Heroku API Key
- Netlify API Token
- Vercel API Token
- Firebase API Key

## Kurulum

```bash
# Repository'yi klonlayın
git clone https://github.com/akaakbas/pipe_sentinel.git
cd pipe_sentinel

# Sanal ortam oluşturun
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Bağımlılıkları yükleyin
pip install -r requirements.txt
```

## Kullanım

```bash
# Tek bir workflow dosyasını analiz et
python -m pipe_sentinel path/to/workflow.yml

# Tüm workflow dosyalarını analiz et
python -m pipe_sentinel path/to/workflows/
```

## Güvenlik

- Tüm analizler yerel olarak çalışır
- Hassas veriler kaydedilmez
- GitHub Secrets kullanımı önerilir
- Minimum yetki prensibi uygulanır

## Katkıda Bulunma

1. Bu repository'yi fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/yeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik: X'`)
4. Branch'inizi push edin (`git push origin feature/yeniOzellik`)
5. Pull Request oluşturun

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## İletişim

- GitHub Issues
- Pull Requests
- E-posta: akbasberke34@gmail.com 