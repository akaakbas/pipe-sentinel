"""
YAML dosyalarının güvenlik analizi için modül
"""

import yaml
import re
import requests
import json
from pathlib import Path
from typing import Dict, List, Optional, Set
from pydantic import BaseModel

class SecurityRisk(BaseModel):
    """Güvenlik riski modeli"""
    risk: str
    severity: str
    line: int
    cve: Optional[str] = None
    fix: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None  # Riskin etki seviyesi
    solution_steps: Optional[List[str]] = None  # Adım adım çözüm süreci
    references: Optional[List[str]] = None  # Güvenlik referansları
    priority: Optional[int] = None  # Öncelik sırası (1: En yüksek)

class WorkflowAnalyzer:
    """Workflow dosyalarının güvenlik analizi için sınıf"""
    
    def __init__(self, workflow_path: Path):
        self.workflow_path = workflow_path
        self.content = self._read_workflow()
        self.risks: List[SecurityRisk] = []
        self._load_known_actions()
        self._load_github_actions()
        
    def _load_known_actions(self):
        """Bilinen güvenli action'ları yükle"""
        # Hem tam isim hem de ana isim ile eşleşecek şekilde whitelist
        self.known_actions = {
            "actions/checkout@v3", "actions/checkout@v4",
            "actions/setup-python@v4", "actions/setup-node@v3",
            "actions/cache@v3", "actions/upload-artifact@v3",
            "actions/download-artifact@v3",
            # Ana isimler (her versiyon için)
            "actions/checkout", "actions/setup-python", "actions/setup-node",
            "actions/cache", "actions/upload-artifact", "actions/download-artifact",
            # Diğer popüler güvenli action'lar
            "github/codeql-action/analyze@v2", "github/codeql-action/init@v2",
            "github/codeql-action/upload-sarif@v2",
            "github/super-linter@v5"
        }

    def _load_github_actions(self):
        """GitHub API ile güncel resmi action'ları çek ve whitelist'e ekle"""
        try:
            response = requests.get("https://api.github.com/repos/actions/actions/contents")
            if response.status_code == 200:
                actions = response.json()
                for action in actions:
                    if action.get("type") == "dir":
                        action_name = f"actions/{action['name']}"
                        self.known_actions.add(action_name)
        except Exception as e:
            print(f"GitHub API ile action listesi çekilirken hata: {e}")

    def _read_workflow(self) -> Dict:
        """Workflow dosyasını oku ve YAML olarak parse et"""
        with open(self.workflow_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _get_line_number(self, content: str, pattern: str) -> int:
        """Belirli bir pattern'in satır numarasını bul"""
        for i, line in enumerate(content.split('\n'), 1):
            if pattern in line:
                return i
        return 0

    def _get_priority(self, severity: str, impact: str) -> int:
        """Risk önceliğini hesapla"""
        severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        impact_weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return severity_weights.get(severity, 0) * impact_weights.get(impact, 0)

    def detect_risky_permissions(self) -> List[SecurityRisk]:
        """Tehlikeli izinleri tespit et"""
        risks = []
        content = self.workflow_path.read_text()
        
        # Tehlikeli izinleri kontrol et
        dangerous_permissions = {
            "contents: write": {
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "İzinleri kısıtlayın: contents: write yerine contents: read kullanın",
                "description": "Bu izin, workflow'un repository içeriğini değiştirmesine izin verir. Bu, yetkisiz değişikliklere veya güvenlik açıklarına yol açabilir.",
                "solution_steps": [
                    "1. GitHub repository ayarlarına gidin",
                    "2. Actions > General > Workflow permissions bölümüne gidin",
                    "3. 'Read and write permissions' yerine 'Read repository contents permission' seçin",
                    "4. Değişiklikleri kaydedin"
                ],
                "references": [
                    "CWE-250: Execution with Unnecessary Privileges",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "packages: write": {
                "severity": "HIGH",
                "impact": "HIGH",
                "fix": "İzinleri kısıtlayın: packages: write yerine packages: read kullanın",
                "description": "Bu izin, workflow'un package'ları değiştirmesine izin verir. Bu, kötü amaçlı paketlerin yüklenmesine yol açabilir.",
                "solution_steps": [
                    "1. GitHub repository ayarlarına gidin",
                    "2. Actions > General > Workflow permissions bölümüne gidin",
                    "3. 'Read and write permissions' yerine 'Read repository contents permission' seçin",
                    "4. Değişiklikleri kaydedin"
                ],
                "references": [
                    "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
                    "OWASP Top 10 2021: A8-Software and Data Integrity Failures"
                ]
            }
        }
        
        if "permissions" in self.content:
            for perm, details in dangerous_permissions.items():
                if perm in str(self.content["permissions"]):
                    line = self._get_line_number(content, perm)
                    priority = self._get_priority(details["severity"], details["impact"])
                    risks.append(SecurityRisk(
                        risk=f"Tehlikeli İzin: {perm}",
                        severity=details["severity"],
                        line=line,
                        cve="CVE-PIPESENTINEL-2024-001",
                        fix=details["fix"],
                        description=details["description"],
                        impact=details["impact"],
                        solution_steps=details["solution_steps"],
                        references=details["references"],
                        priority=priority
                    ))
        
        return risks

    def detect_secret_leaks(self) -> List[SecurityRisk]:
        """Secret sızıntılarını tespit et"""
        risks = []
        content = self.workflow_path.read_text()

        # Gelişmiş secret pattern'leri
        secret_patterns = {
            "AWS_ACCESS_KEY": {
                "pattern": r'AKIA[0-9A-Z]{16}',
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "AWS kimlik bilgilerini GitHub Secrets'ta saklayın",
                "description": "AWS Access Key doğrudan workflow dosyasında bulundu. Bu, yetkisiz erişim ve veri sızıntısı riski oluşturur.",
                "solution_steps": [
                    "1. AWS Console'da mevcut Access Key'i devre dışı bırakın",
                    "2. Yeni bir Access Key oluşturun",
                    "3. GitHub repository ayarlarına gidin",
                    "4. Settings > Secrets and variables > Actions'a gidin",
                    "5. 'New repository secret' butonuna tıklayın",
                    "6. Name: AWS_ACCESS_KEY, Value: [yeni access key] şeklinde ekleyin",
                    "7. Workflow dosyasında ${{ secrets.AWS_ACCESS_KEY }} şeklinde kullanın"
                ],
                "references": [
                    "CWE-798: Use of Hard-coded Credentials",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "STRIPE_API_KEY": {
                "pattern": r'(sk|pk)_(test|live)_[0-9a-zA-Z]{24}',
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "Stripe API anahtarlarını GitHub Secrets'ta saklayın",
                "description": "Stripe API anahtarı doğrudan workflow dosyasında bulundu. Bu, ödeme sistemine yetkisiz erişim riski oluşturur.",
                "solution_steps": [
                    "1. Stripe Dashboard'da mevcut API anahtarını devre dışı bırakın",
                    "2. Yeni bir API anahtarı oluşturun",
                    "3. GitHub Secrets'a ekleyin",
                    "4. Workflow'da ${{ secrets.STRIPE_API_KEY }} şeklinde kullanın"
                ],
                "references": [
                    "CWE-798: Use of Hard-coded Credentials",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "TWILIO_AUTH_TOKEN": {
                "pattern": r'[0-9a-fA-F]{32}',
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "Twilio kimlik bilgilerini GitHub Secrets'ta saklayın",
                "description": "Twilio Auth Token doğrudan workflow dosyasında bulundu. Bu, SMS ve arama servislerine yetkisiz erişim riski oluşturur.",
                "solution_steps": [
                    "1. Twilio Console'da mevcut Auth Token'ı değiştirin",
                    "2. Yeni bir Auth Token oluşturun",
                    "3. GitHub Secrets'a ekleyin",
                    "4. Workflow'da ${{ secrets.TWILIO_AUTH_TOKEN }} şeklinde kullanın"
                ],
                "references": [
                    "CWE-798: Use of Hard-coded Credentials",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "SENDGRID_API_KEY": {
                "pattern": r'SG\.[0-9a-zA-Z]{32}\.[0-9a-zA-Z]{32}',
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "SendGrid API anahtarını GitHub Secrets'ta saklayın",
                "description": "SendGrid API anahtarı doğrudan workflow dosyasında bulundu. Bu, e-posta servisine yetkisiz erişim riski oluşturur.",
                "solution_steps": [
                    "1. SendGrid Dashboard'da mevcut API anahtarını devre dışı bırakın",
                    "2. Yeni bir API anahtarı oluşturun",
                    "3. GitHub Secrets'a ekleyin",
                    "4. Workflow'da ${{ secrets.SENDGRID_API_KEY }} şeklinde kullanın"
                ],
                "references": [
                    "CWE-798: Use of Hard-coded Credentials",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "DIGITALOCEAN_API_TOKEN": {
                "pattern": r'[0-9a-fA-F]{64}',
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "DigitalOcean API token'ını GitHub Secrets'ta saklayın",
                "description": "DigitalOcean API token'ı doğrudan workflow dosyasında bulundu. Bu, bulut altyapısına yetkisiz erişim riski oluşturur.",
                "solution_steps": [
                    "1. DigitalOcean Dashboard'da mevcut token'ı devre dışı bırakın",
                    "2. Yeni bir token oluşturun",
                    "3. GitHub Secrets'a ekleyin",
                    "4. Workflow'da ${{ secrets.DIGITALOCEAN_API_TOKEN }} şeklinde kullanın"
                ],
                "references": [
                    "CWE-798: Use of Hard-coded Credentials",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "HEROKU_API_KEY": {
                "pattern": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "Heroku API anahtarını GitHub Secrets'ta saklayın",
                "description": "Heroku API anahtarı doğrudan workflow dosyasında bulundu. Bu, uygulama yönetimine yetkisiz erişim riski oluşturur.",
                "solution_steps": [
                    "1. Heroku Dashboard'da mevcut API anahtarını devre dışı bırakın",
                    "2. Yeni bir API anahtarı oluşturun",
                    "3. GitHub Secrets'a ekleyin",
                    "4. Workflow'da ${{ secrets.HEROKU_API_KEY }} şeklinde kullanın"
                ],
                "references": [
                    "CWE-798: Use of Hard-coded Credentials",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "NETLIFY_API_TOKEN": {
                "pattern": r'[0-9a-fA-F]{40}',
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "Netlify API token'ını GitHub Secrets'ta saklayın",
                "description": "Netlify API token'ı doğrudan workflow dosyasında bulundu. Bu, site yönetimine yetkisiz erişim riski oluşturur.",
                "solution_steps": [
                    "1. Netlify Dashboard'da mevcut token'ı devre dışı bırakın",
                    "2. Yeni bir token oluşturun",
                    "3. GitHub Secrets'a ekleyin",
                    "4. Workflow'da ${{ secrets.NETLIFY_API_TOKEN }} şeklinde kullanın"
                ],
                "references": [
                    "CWE-798: Use of Hard-coded Credentials",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "VERCEL_API_TOKEN": {
                "pattern": r'[0-9a-zA-Z]{24}',
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "Vercel API token'ını GitHub Secrets'ta saklayın",
                "description": "Vercel API token'ı doğrudan workflow dosyasında bulundu. Bu, deployment yönetimine yetkisiz erişim riski oluşturur.",
                "solution_steps": [
                    "1. Vercel Dashboard'da mevcut token'ı devre dışı bırakın",
                    "2. Yeni bir token oluşturun",
                    "3. GitHub Secrets'a ekleyin",
                    "4. Workflow'da ${{ secrets.VERCEL_API_TOKEN }} şeklinde kullanın"
                ],
                "references": [
                    "CWE-798: Use of Hard-coded Credentials",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "FIREBASE_API_KEY": {
                "pattern": r'AIza[0-9A-Za-z-_]{35}',
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "Firebase API anahtarını GitHub Secrets'ta saklayın",
                "description": "Firebase API anahtarı doğrudan workflow dosyasında bulundu. Bu, veritabanı ve kimlik doğrulama servislerine yetkisiz erişim riski oluşturur.",
                "solution_steps": [
                    "1. Firebase Console'da mevcut API anahtarını devre dışı bırakın",
                    "2. Yeni bir API anahtarı oluşturun",
                    "3. GitHub Secrets'a ekleyin",
                    "4. Workflow'da ${{ secrets.FIREBASE_API_KEY }} şeklinde kullanın"
                ],
                "references": [
                    "CWE-798: Use of Hard-coded Credentials",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            }
        }

        for secret_type, details in secret_patterns.items():
            matches = re.finditer(details["pattern"], content, re.IGNORECASE)
            for match in matches:
                line = content[:match.start()].count('\n') + 1
                priority = self._get_priority(details["severity"], details["impact"])
                risks.append(SecurityRisk(
                    risk=f"Hardcoded {secret_type} Tespit Edildi",
                    severity=details["severity"],
                    line=line,
                    cve="CVE-PIPESENTINEL-2024-002",
                    fix=details["fix"],
                    description=details["description"],
                    impact=details["impact"],
                    solution_steps=details["solution_steps"],
                    references=details["references"],
                    priority=priority
                ))

        return risks

    def detect_third_party_actions(self) -> List[SecurityRisk]:
        """Üçüncü parti action'ları tespit et"""
        risks = []
        content = self.workflow_path.read_text()

        # Action kullanımlarını bul
        action_pattern = r'uses:\s*([^\s]+)'
        matches = re.finditer(action_pattern, content)

        for match in matches:
            action = match.group(1)
            line = content[:match.start()].count('\n') + 1

            # Bilinen action'ları kontrol et
            action_base = action.split('@')[0]
            if action not in self.known_actions and action_base not in self.known_actions:
                priority = self._get_priority("HIGH", "HIGH")
                risks.append(SecurityRisk(
                    risk=f"Bilinmeyen Üçüncü Parti Action: {action}",
                    severity="HIGH",
                    line=line,
                    cve="CVE-PIPESENTINEL-2024-003",
                    fix="Sadece güvenilir ve resmi action'ları kullanın",
                    description=f"Bu action ({action}) bilinen güvenli action'lar listesinde yok. Üçüncü parti action'lar güvenlik riski oluşturabilir.",
                    impact="HIGH",
                    solution_steps=[
                        "1. Action'ın kaynak kodunu ve güvenlik geçmişini inceleyin",
                        "2. Action'ın GitHub Marketplace'deki popülerliğini ve yıldız sayısını kontrol edin",
                        "3. Action'ın son güncelleme tarihini kontrol edin",
                        "4. Alternatif olarak resmi GitHub action'larını kullanın",
                        "5. Eğer kullanılacaksa, action'ı fork'layıp kendi repository'nizde barındırın"
                    ],
                    references=[
                        "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
                        "OWASP Top 10 2021: A8-Software and Data Integrity Failures"
                    ],
                    priority=priority
                ))

        return risks

    def detect_dangerous_commands(self) -> List[SecurityRisk]:
        """Tehlikeli komutları tespit et"""
        risks = []
        content = self.workflow_path.read_text()
        
        dangerous_commands = {
            "chmod 777": {
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "Daha kısıtlı izinler kullanın",
                "description": "Bu komut tüm kullanıcılara tam okuma, yazma ve çalıştırma izni verir.",
                "solution_steps": [
                    "1. Mevcut dosya izinlerini kontrol edin: ls -l [dosya]",
                    "2. Gerekli minimum izinleri belirleyin",
                    "3. Daha kısıtlı izinler uygulayın: chmod 755 [dosya]",
                    "4. İzinleri doğrulayın: ls -l [dosya]"
                ],
                "references": [
                    "CWE-732: Incorrect Permission Assignment for Critical Resource",
                    "OWASP Top 10 2021: A4-Insecure Design"
                ]
            },
            "curl -X POST": {
                "severity": "HIGH",
                "impact": "HIGH",
                "fix": "Güvenli HTTP istekleri için SSL/TLS kullanın",
                "description": "Bu komut güvenli olmayan HTTP istekleri yapabilir ve hassas verilerin açığa çıkmasına neden olabilir.",
                "solution_steps": [
                    "1. SSL/TLS sertifikasını edinin",
                    "2. curl komutunu güvenli parametrelerle kullanın",
                    "3. İstekleri test edin",
                    "4. Hata durumlarını kontrol edin"
                ],
                "references": [
                    "CWE-319: Cleartext Transmission of Sensitive Information",
                    "OWASP Top 10 2021: A2-Cryptographic Failures"
                ]
            },
            "wget": {
                "severity": "MEDIUM",
                "impact": "MEDIUM",
                "fix": "SSL/TLS doğrulamasını etkinleştirin",
                "description": "Bu komut güvenli olmayan indirmeler yapabilir ve kötü amaçlı içeriğin sisteme girmesine neden olabilir.",
                "solution_steps": [
                    "1. SSL/TLS sertifikasını edinin",
                    "2. wget --ca-certificate=/path/to/cert.pem kullanın",
                    "3. İndirilen dosyaları doğrulayın",
                    "4. Güvenli kaynaklardan indirme yapın"
                ],
                "references": [
                    "CWE-494: Download of Code Without Integrity Check",
                    "OWASP Top 10 2021: A8-Software and Data Integrity Failures"
                ]
            },
            "cat /etc/passwd": {
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "Sistem dosyalarına erişim yerine güvenli alternatifler kullanın",
                "description": "Bu komut sistem kullanıcı bilgilerini açığa çıkarır ve potansiyel olarak brute force saldırılarına zemin hazırlar.",
                "solution_steps": [
                    "1. Kullanıcı bilgileri için 'id' komutunu kullanın",
                    "2. Gerekli minimum yetkilerle çalışın",
                    "3. Hassas sistem dosyalarına erişimi kısıtlayın",
                    "4. Güvenlik duvarı kurallarını gözden geçirin"
                ],
                "references": [
                    "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                    "OWASP Top 10 2021: A1-Broken Access Control"
                ]
            },
            "rm -rf": {
                "severity": "HIGH",
                "impact": "HIGH",
                "fix": "Daha güvenli silme işlemleri için interactive mod kullanın",
                "description": "Bu komut geri alınamaz veri kaybına neden olabilir. Özellikle root dizininde kullanıldığında tüm sistemi silebilir.",
                "solution_steps": [
                    "1. rm -i kullanarak interactive mod etkinleştirin",
                    "2. rm --preserve-root ile root dizinini koruyun",
                    "3. Silinecek dosyaları önceden listeleyin",
                    "4. Yedek alın ve test edin"
                ],
                "references": [
                    "CWE-212: Improper Removal of Sensitive Information Before Storage or Transfer",
                    "OWASP Top 10 2021: A4-Insecure Design"
                ]
            },
            "sudo": {
                "severity": "HIGH",
                "impact": "HIGH",
                "fix": "Sudo yerine daha kısıtlı yetkilerle çalışan komutlar kullanın",
                "description": "Bu komut root yetkisiyle çalıştırma imkanı sağlar ve yetkisiz erişim riski oluşturur.",
                "solution_steps": [
                    "1. Belirli komutlar için sudoers dosyasında özel izinler tanımlayın",
                    "2. Minimum yetki prensibini uygulayın",
                    "3. Komut çalıştırma geçmişini loglayın",
                    "4. Düzenli güvenlik denetimi yapın"
                ],
                "references": [
                    "CWE-250: Execution with Unnecessary Privileges",
                    "OWASP Top 10 2021: A7-Identification and Authentication Failures"
                ]
            },
            "nc -l": {
                "severity": "CRITICAL",
                "impact": "HIGH",
                "fix": "Netcat yerine güvenli iletişim protokolleri kullanın",
                "description": "Bu komut açık bir port dinlemesi başlatır ve potansiyel olarak yetkisiz erişime zemin hazırlar.",
                "solution_steps": [
                    "1. Netcat kullanımını kaldırın",
                    "2. SSH veya TLS gibi güvenli protokoller kullanın",
                    "3. Port dinleme işlemlerini kısıtlayın",
                    "4. Güvenlik duvarı kurallarını gözden geçirin"
                ],
                "references": [
                    "CWE-284: Improper Access Control",
                    "OWASP Top 10 2021: A1-Broken Access Control"
                ]
            },
            "chattr +i": {
                "severity": "HIGH",
                "impact": "MEDIUM",
                "fix": "Dosya özniteliklerini güvenli bir şekilde yönetin",
                "description": "Bu komut dosyaları değiştirilemez yapar ve sistem yönetimini zorlaştırabilir.",
                "solution_steps": [
                    "1. Dosya izinlerini daha güvenli bir şekilde yönetin",
                    "2. ACL (Access Control Lists) kullanın",
                    "3. Dosya özniteliklerini düzenli kontrol edin",
                    "4. Yedekleme stratejisi oluşturun"
                ],
                "references": [
                    "CWE-732: Incorrect Permission Assignment for Critical Resource",
                    "OWASP Top 10 2021: A4-Insecure Design"
                ]
            },
            "dd if=": {
                "severity": "HIGH",
                "impact": "HIGH",
                "fix": "Disk işlemleri için güvenli alternatifler kullanın",
                "description": "Bu komut düşük seviyeli disk işlemleri yapar ve veri kaybına neden olabilir.",
                "solution_steps": [
                    "1. Yüksek seviyeli disk yönetim araçları kullanın",
                    "2. İşlem öncesi yedek alın",
                    "3. Test ortamında deneyin",
                    "4. Hata kontrolü ekleyin"
                ],
                "references": [
                    "CWE-212: Improper Removal of Sensitive Information",
                    "OWASP Top 10 2021: A4-Insecure Design"
                ]
            }
        }
        
        for cmd, details in dangerous_commands.items():
            if cmd in content:
                line = self._get_line_number(content, cmd)
                priority = self._get_priority(details["severity"], details["impact"])
                risks.append(SecurityRisk(
                    risk=f"Tehlikeli Komut: {cmd}",
                    severity=details["severity"],
                    line=line,
                    cve="CVE-PIPESENTINEL-2024-004",
                    fix=details["fix"],
                    description=details["description"],
                    impact=details["impact"],
                    solution_steps=details["solution_steps"],
                    references=details["references"],
                    priority=priority
                ))
        
        return risks

    def analyze(self) -> List[SecurityRisk]:
        """Tüm güvenlik analizlerini çalıştır"""
        self.risks.extend(self.detect_risky_permissions())
        self.risks.extend(self.detect_secret_leaks())
        self.risks.extend(self.detect_third_party_actions())
        self.risks.extend(self.detect_dangerous_commands())
        
        # Riskleri öncelik sırasına göre sırala
        self.risks.sort(key=lambda x: x.priority if x.priority else 0, reverse=True)
        
        return self.risks 